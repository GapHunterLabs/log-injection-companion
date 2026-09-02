package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.psi.JavaTokenType
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiPolyadicExpression
import com.intellij.psi.PsiReferenceExpression

/**
 * Whether [expression] is a BARE reference to [targetName], or a `+`
 * concatenation where at least one operand is (same "direct reference
 * or one-hop concatenation" taint shape this catalog's other sink
 * finders already use).
 *
 * **Sanitization, stated honestly:** any wrapping method call around
 * the reference (`param.replace("\n", "")`, but equally a genuinely
 * inert call) breaks the chain -- neither this function nor any
 * caller descends into a [com.intellij.psi.PsiMethodCallExpression]
 * looking for the reference inside it, so a call-wrapped reference is
 * always treated as sanitized. This is a deliberate v0.1
 * simplification (never a guess in the unsafe direction: it can only
 * under-report, never over-report).
 */
object TaintReferenceMatcher {

    fun isTaintedReference(expression: PsiExpression, targetName: String): Boolean = when (expression) {
        is PsiReferenceExpression -> expression.referenceName == targetName && expression.qualifierExpression == null
        is PsiPolyadicExpression -> expression.operationTokenType == JavaTokenType.PLUS &&
            expression.operands.any { isTaintedReference(it, targetName) }
        else -> false
    }
}
