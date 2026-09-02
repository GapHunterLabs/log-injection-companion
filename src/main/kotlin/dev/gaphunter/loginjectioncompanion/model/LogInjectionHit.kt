package dev.gaphunter.loginjectioncompanion.model

import com.intellij.psi.PsiElement

/** A confirmed CRLF log injection: [parameterName] (an HTTP endpoint parameter) reaches a logging call unsanitized -- either directly in the same method, or transitively through the whole-project interprocedural call graph. [anchor] is the log call (direct case) or the forwarding call site (transitive case) that proves it. */
data class LogInjectionHit(val anchor: PsiElement, val parameterName: String)
