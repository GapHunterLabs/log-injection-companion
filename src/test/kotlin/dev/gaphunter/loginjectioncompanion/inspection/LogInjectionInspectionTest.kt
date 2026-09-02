package dev.gaphunter.loginjectioncompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

/** Assertions match on this plugin's own distinctive message text ("CWE-117"), never a generic word, for the same reason documented in this catalog's other plugins' test suites (avoiding an unrelated compiler diagnostic false match). */
class LogInjectionInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(LogInjectionInspection::class.java)
    }

    private val loggerImports = """
        import org.slf4j.Logger;
        import org.slf4j.LoggerFactory;
        import org.springframework.web.bind.annotation.GetMapping;
    """.trimIndent()

    fun `test a direct log call with an endpoint parameter is flagged`() {
        myFixture.configureByText(
            "DirectController.java",
            "$loggerImports\n\n" + """
            class DirectController {
                private static final Logger log = LoggerFactory.getLogger(DirectController.class);

                @GetMapping("/direct")
                void handle(String userInput) {
                    log.info(userInput);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-117") == true && it.description?.contains("userInput") == true })
    }

    fun `test a one-hop transitive call to a helper that logs is flagged`() {
        myFixture.configureByText(
            "TransitiveController.java",
            "$loggerImports\n\n" + """
            class TransitiveController {
                private static final Logger log = LoggerFactory.getLogger(TransitiveController.class);

                @GetMapping("/transitive")
                void handle(String userInput) {
                    logMessage(userInput);
                }

                private void logMessage(String msg) {
                    log.warn(msg);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-117") == true && it.description?.contains("userInput") == true })
    }

    fun `test a real two-hop chain through two different helpers is flagged`() {
        myFixture.configureByText(
            "ChainController.java",
            "$loggerImports\n\n" + """
            class ChainController {
                private static final Logger log = LoggerFactory.getLogger(ChainController.class);

                @GetMapping("/chain")
                void handle(String userInput) {
                    step1(userInput);
                }

                private void step1(String a) {
                    step2(a);
                }

                private void step2(String b) {
                    log.error(b);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-117") == true && it.description?.contains("userInput") == true })
    }

    fun `test a real mutual-recursion cycle between two helpers terminates and is still flagged`() {
        myFixture.configureByText(
            "CycleController.java",
            "$loggerImports\n\n" + """
            class CycleController {
                private static final Logger log = LoggerFactory.getLogger(CycleController.class);

                @GetMapping("/cycle")
                void handle(String userInput) {
                    ping(userInput);
                }

                private void ping(String a) {
                    pong(a);
                }

                private void pong(String b) {
                    log.info(b);
                    ping(b);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-117") == true && it.description?.contains("userInput") == true })
    }

    fun `test a sanitized argument via replace is not flagged`() {
        myFixture.configureByText(
            "SanitizedController.java",
            "$loggerImports\n\n" + """
            class SanitizedController {
                private static final Logger log = LoggerFactory.getLogger(SanitizedController.class);

                @GetMapping("/safe")
                void handle(String userInput) {
                    log.info(userInput.replace("\n", "").replace("\r", ""));
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-117") == true })
    }

    fun `test a non-endpoint method with the same shape is not flagged`() {
        myFixture.configureByText(
            "PlainClass.java",
            "$loggerImports\n\n" + """
            class PlainClass {
                private static final Logger log = LoggerFactory.getLogger(PlainClass.class);

                void handle(String userInput) {
                    log.info(userInput);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-117") == true })
    }

    fun `test logging a local constant unrelated to the parameter is not flagged`() {
        myFixture.configureByText(
            "UnrelatedController.java",
            "$loggerImports\n\n" + """
            class UnrelatedController {
                private static final Logger log = LoggerFactory.getLogger(UnrelatedController.class);

                @GetMapping("/unrelated")
                void handle(String userInput) {
                    String trusted = "constant-value";
                    log.info(trusted);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-117") == true })
    }
}
