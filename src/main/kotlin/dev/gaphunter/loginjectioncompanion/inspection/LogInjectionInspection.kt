package dev.gaphunter.loginjectioncompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import dev.gaphunter.loginjectioncompanion.detect.LogInjectionFinder
import dev.gaphunter.loginjectioncompanion.model.LogInjectionHit
import dev.gaphunter.loginjectioncompanion.review.ReviewPrompt

/** Flags an unsanitized logging call reachable from an HTTP endpoint parameter -- CWE-117. See [LogInjectionFinder]. */
class LogInjectionInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null

        val hits = LogInjectionFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber:${hit.parameterName}")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: LogInjectionHit): String =
        "Endpoint parameter '${hit.parameterName}' reaches this logging call unsanitized (directly, or through the project's own " +
            "call graph) -- an attacker can inject a CRLF sequence to forge log entries (CWE-117)"
}
