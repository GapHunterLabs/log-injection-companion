package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Key
import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiJavaFile
import com.intellij.psi.PsiManager
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope
import com.intellij.psi.util.CachedValue
import com.intellij.psi.util.CachedValueProvider
import com.intellij.psi.util.CachedValuesManager
import com.intellij.psi.util.PsiModificationTracker

/**
 * Real whole-project interprocedural taint analysis for CWE-117 (Log
 * Injection) -- the hardest algorithmic technique in this catalog:
 * builds the real project call graph (method -> methods it calls,
 * resolved only to OTHER methods this project has source for),
 * condenses it into strongly connected components via
 * [TarjanSccComputer] (real Tarjan's algorithm, the base technique a
 * genuine interprocedural dataflow framework needs for correctness
 * under recursion/mutual recursion), then computes a real FIXED POINT
 * per method: which of ITS OWN parameters, if tainted, reach an
 * unsanitized logging call -- either directly in its own body, or
 * transitively through a call to another project method whose summary
 * already proves the SAME thing for one of ITS parameters, fed by this
 * method's parameter at that exact call site.
 *
 * SCCs are processed in the order Tarjan produces them (callees before
 * callers); a cyclic SCC (mutual recursion) is iterated internally
 * until its members' summaries stop changing -- a genuine fixed-point
 * computation, not just one pass.
 *
 * Cached per-project via [CachedValuesManager], keyed by
 * [MethodKey.of] (a text key, never a raw [PsiMethod], see that
 * object's own doc for why).
 *
 * **Cancellable, per catalog-wide precedent:** this computation runs
 * inside a `LocalInspectionTool`'s read action, but a pure in-memory
 * fixed-point loop is not automatically interruptible -- a large real
 * project could otherwise block the read action uncancellably while
 * the user keeps typing. [ProgressManager.checkCanceled] is called
 * once per file during the initial scan and once per outer
 * fixed-point iteration per SCC (retrofitted here 2026-09-03 after a
 * catalog-wide review found it missing).
 *
 * **v0.1 scope, stated honestly:** only project methods (a call into a
 * compiled library/dependency terminates that branch -- assumed
 * unknown, never inferred); taint only flows through a bare parameter
 * reference or a `+` concatenation containing one (see
 * [TaintReferenceMatcher] -- any wrapping method call, sanitizing or
 * not, breaks the chain); a project with more than [MAX_METHODS]
 * total analyzable methods skips analysis entirely rather than risk
 * pathological cost.
 */
object ProjectLogTaintAnalyzer {

    const val MAX_METHODS = 3000
    private const val MAX_FILE_LENGTH = 500_000

    private val CACHE_KEY: Key<CachedValue<Map<String, Map<Int, PsiElement>>>> = Key.create("logInjectionCompanion.summaries")

    fun summariesFor(project: Project): Map<String, Map<Int, PsiElement>> {
        return CachedValuesManager.getManager(project).getCachedValue(
            project,
            CACHE_KEY,
            { CachedValueProvider.Result.create(computeSummaries(project), PsiModificationTracker.MODIFICATION_COUNT) },
            false,
        )
    }

    private fun computeSummaries(project: Project): Map<String, Map<Int, PsiElement>> {
        val scope = GlobalSearchScope.projectScope(project)
        val files = FilenameIndex.getAllFilesByExt(project, "java", scope)
        val psiManager = PsiManager.getInstance(project)

        val allMethods = mutableListOf<PsiMethod>()
        for (virtualFile in files) {
            ProgressManager.checkCanceled()
            val psiFile = psiManager.findFile(virtualFile) as? PsiJavaFile ?: continue
            if (psiFile.text.length > MAX_FILE_LENGTH) continue
            psiFile.accept(object : JavaRecursiveElementWalkingVisitor() {
                override fun visitMethod(method: PsiMethod) {
                    super.visitMethod(method)
                    if (method.body != null) allMethods += method
                }
            })
        }
        if (allMethods.size > MAX_METHODS) return emptyMap()

        val methodSet = allMethods.toHashSet()
        val graph: Map<PsiMethod, List<PsiMethod>> = allMethods.associateWith { method -> calleesOf(method, methodSet) }

        val sccsCalleesFirst = TarjanSccComputer(graph).compute()
        val summaries = HashMap<PsiMethod, Map<Int, PsiElement>>()
        for (scc in sccsCalleesFirst) {
            var changed = true
            while (changed) {
                ProgressManager.checkCanceled()
                changed = false
                for (method in scc) {
                    val previous = summaries[method]
                    val recomputed = summaryForMethod(method, summaries)
                    if (recomputed.keys != previous?.keys) {
                        summaries[method] = recomputed
                        changed = true
                    }
                }
            }
        }

        return summaries.entries.associate { (method, summary) -> MethodKey.of(method) to summary }
    }

    private fun calleesOf(method: PsiMethod, methodSet: Set<PsiMethod>): List<PsiMethod> {
        val body = method.body ?: return emptyList()
        val callees = mutableListOf<PsiMethod>()
        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                super.visitMethodCallExpression(call)
                val resolved = call.resolveMethod() ?: return
                if (resolved in methodSet) callees += resolved
            }
        })
        return callees
    }

    /** [Int] parameter index -> the anchor proving that tainting that parameter reaches a logging call, either directly in [method]'s own body or transitively via a call whose target's summary (looked up in [summaries], possibly still partial mid-fixed-point) already proves it. */
    private fun summaryForMethod(method: PsiMethod, summaries: Map<PsiMethod, Map<Int, PsiElement>>): Map<Int, PsiElement> {
        val body = method.body ?: return emptyMap()
        val paramNames = method.parameterList.parameters.map { it.name }
        val result = LinkedHashMap<Int, PsiElement>()

        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                super.visitMethodCallExpression(call)

                if (LoggingCallSignals.isLoggingCall(call)) {
                    for (argument in call.argumentList.expressions) {
                        recordFirstMatch(result, paramNames, argument, call.methodExpression.referenceNameElement ?: call.methodExpression)
                    }
                    return
                }

                val callee = call.resolveMethod() ?: return
                val calleeSummary = summaries[callee] ?: return
                val arguments = call.argumentList.expressions
                for (calleeParamIndex in calleeSummary.keys) {
                    val argument = arguments.getOrNull(calleeParamIndex) ?: continue
                    recordFirstMatch(result, paramNames, argument, call.methodExpression.referenceNameElement ?: call.methodExpression)
                }
            }
        })
        return result
    }

    private fun recordFirstMatch(result: MutableMap<Int, PsiElement>, paramNames: List<String>, argument: PsiExpression, anchor: PsiElement) {
        for ((index, name) in paramNames.withIndex()) {
            if (index !in result && TaintReferenceMatcher.isTaintedReference(argument, name)) {
                result[index] = anchor
            }
        }
    }
}
