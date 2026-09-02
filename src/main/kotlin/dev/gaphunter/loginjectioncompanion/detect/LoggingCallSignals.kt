package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiReferenceExpression
import com.intellij.psi.PsiVariable

/**
 * Recognizes a real logging call (`log.info(...)`/`logger.warn(...)`/
 * etc.) -- by the qualifier's own reference NAME (`log`/`logger`, the
 * near-universal SLF4J/Log4j2/Lombok `@Slf4j` field-naming convention)
 * OR by the qualifier's declared type TEXT mentioning `Logger`. Text
 * only, deliberately never resolved against the real logging
 * framework's classpath -- same reasoning as this catalog's other
 * sink-finder plugins' `looksLikeXxx` heuristics.
 */
object LoggingCallSignals {

    private val LOG_METHOD_NAMES = setOf("info", "warn", "error", "debug", "trace")

    fun isLoggingCall(call: PsiMethodCallExpression): Boolean {
        if (call.methodExpression.referenceName !in LOG_METHOD_NAMES) return false
        val qualifier = call.methodExpression.qualifierExpression as? PsiReferenceExpression ?: return false

        val qualifierName = qualifier.referenceName?.lowercase()
        if (qualifierName == "log" || qualifierName == "logger") return true

        val resolvedVariable = qualifier.resolve() as? PsiVariable ?: return false
        return resolvedVariable.type.presentableText.contains("Logger")
    }
}
