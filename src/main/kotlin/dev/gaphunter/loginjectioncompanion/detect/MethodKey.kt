package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.psi.PsiMethod

/**
 * A stable, TEXT-only identity for a method, used as the key of
 * [ProjectLogTaintAnalyzer]'s cached whole-project summary map --
 * deliberately never the raw [PsiMethod] object itself as a map key
 * across a `CachedValuesManager` cache boundary. A [PsiMethod] read
 * fresh inside `checkFile` for the CURRENT file and the "same" method
 * as seen by the project-wide scan that built the cache are not
 * guaranteed to be the identical object/reference in every platform
 * version -- a text key sidesteps that identity question entirely
 * (the same, simpler discipline this catalog's other whole-project
 * plugins already use by keying their own maps with plain strings --
 * role names, topic names, file names -- never a raw PSI element).
 */
object MethodKey {
    fun of(method: PsiMethod): String {
        val className = method.containingClass?.qualifiedName ?: method.containingClass?.name ?: "?"
        val params = method.parameterList.parameters.joinToString(",") { it.type.presentableText }
        return "$className#${method.name}($params)"
    }
}
