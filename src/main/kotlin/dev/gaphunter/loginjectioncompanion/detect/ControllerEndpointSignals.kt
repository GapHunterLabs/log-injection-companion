package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.psi.PsiAnnotation
import com.intellij.psi.PsiMethod

/** A closed, known list of Spring MVC/JAX-RS annotations that mark a method as an HTTP endpoint -- every parameter is treated as untrusted. Same convention (and same copy-per-plugin) as this catalog's other sink-finder plugins. */
object ControllerEndpointSignals {

    private val METHOD_MAPPING_ANNOTATIONS = setOf(
        "PostMapping", "GetMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping",
        "POST", "GET", "PUT", "DELETE", "PATCH",
    )

    fun isEndpointMethod(method: PsiMethod): Boolean =
        method.modifierList.annotations.any { it.simpleNameMatches(METHOD_MAPPING_ANNOTATIONS) }

    private fun PsiAnnotation.simpleNameMatches(names: Set<String>): Boolean =
        nameReferenceElement?.referenceName in names
}
