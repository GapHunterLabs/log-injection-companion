package dev.gaphunter.loginjectioncompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure, PSI-free tests of the SCC algorithm itself, on synthetic string-node graphs. */
class TarjanSccComputerTest {

    private fun sccIndexOf(sccs: List<List<String>>, node: String): Int =
        sccs.indexOfFirst { node in it }

    @Test
    fun `a simple chain with no cycles produces one SCC per node`() {
        val graph = mapOf("A" to listOf("B"), "B" to listOf("C"), "C" to emptyList())
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(3, sccs.size)
        assertTrue(sccs.all { it.size == 1 })
        // Callees before callers: C's SCC must appear before B's, which must appear before A's.
        assertTrue(sccIndexOf(sccs, "C") < sccIndexOf(sccs, "B"))
        assertTrue(sccIndexOf(sccs, "B") < sccIndexOf(sccs, "A"))
    }

    @Test
    fun `a two-node cycle produces one SCC containing both nodes`() {
        val graph = mapOf("A" to listOf("B"), "B" to listOf("A"))
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(1, sccs.size)
        assertEquals(setOf("A", "B"), sccs.single().toSet())
    }

    @Test
    fun `a self-loop produces a single-node SCC`() {
        val graph = mapOf("A" to listOf("A"))
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(1, sccs.size)
        assertEquals(listOf("A"), sccs.single())
    }

    @Test
    fun `a three-node cycle plus an external caller orders the cycle before the caller`() {
        // A -> B -> C -> A (a real cycle), D -> A (D calls into the cycle but isn't part of it).
        val graph = mapOf(
            "A" to listOf("B"),
            "B" to listOf("C"),
            "C" to listOf("A"),
            "D" to listOf("A"),
        )
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(2, sccs.size) // {A,B,C} and {D}
        val cycleIndex = sccIndexOf(sccs, "A")
        assertEquals(cycleIndex, sccIndexOf(sccs, "B"))
        assertEquals(cycleIndex, sccIndexOf(sccs, "C"))
        assertTrue(cycleIndex < sccIndexOf(sccs, "D"))
    }

    @Test
    fun `two disconnected chains each keep their own internal callee-before-caller order`() {
        val graph = mapOf("A" to listOf("B"), "B" to emptyList(), "C" to listOf("D"), "D" to emptyList())
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(4, sccs.size)
        assertTrue(sccIndexOf(sccs, "B") < sccIndexOf(sccs, "A"))
        assertTrue(sccIndexOf(sccs, "D") < sccIndexOf(sccs, "C"))
    }

    @Test
    fun `an empty graph produces no SCCs`() {
        assertTrue(TarjanSccComputer<String>(emptyMap()).compute().isEmpty())
    }

    @Test
    fun `a diamond shape (A calls B and C, both call D) produces four singleton SCCs with D first`() {
        val graph = mapOf("A" to listOf("B", "C"), "B" to listOf("D"), "C" to listOf("D"), "D" to emptyList())
        val sccs = TarjanSccComputer(graph).compute()
        assertEquals(4, sccs.size)
        assertTrue(sccIndexOf(sccs, "D") < sccIndexOf(sccs, "B"))
        assertTrue(sccIndexOf(sccs, "D") < sccIndexOf(sccs, "C"))
        assertTrue(sccIndexOf(sccs, "B") < sccIndexOf(sccs, "A"))
        assertTrue(sccIndexOf(sccs, "C") < sccIndexOf(sccs, "A"))
    }
}
