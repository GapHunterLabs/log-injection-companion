package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiMethod
import dev.gaphunter.loginjectioncompanion.model.LogInjectionHit

/**
 * Finds every HTTP endpoint method in [PsiFile] and looks up its
 * whole-project taint summary ([ProjectLogTaintAnalyzer]) -- a
 * non-empty summary means at least one of the endpoint's own
 * parameters, if attacker-controlled (which it always is, by
 * definition of being a controller parameter), reaches an unsanitized
 * logging call somewhere in the real interprocedural call graph.
 */
object LogInjectionFinder {

    fun findAll(file: PsiFile): List<LogInjectionHit> {
        val hits = mutableListOf<LogInjectionHit>()
        val project = file.project
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                if (!ControllerEndpointSignals.isEndpointMethod(method)) return

                val summary = ProjectLogTaintAnalyzer.summariesFor(project)[MethodKey.of(method)] ?: return
                val paramNames = method.parameterList.parameters.map { it.name }
                for ((index, anchor) in summary) {
                    hits += LogInjectionHit(anchor, paramNames.getOrNull(index) ?: "<param>")
                }
            }
        })
        return hits
    }
}
