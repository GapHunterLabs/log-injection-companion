package dev.gaphunter.loginjectioncompanion.detect

import com.intellij.openapi.progress.ProgressManager

/**
 * Real Tarjan's Strongly Connected Components algorithm over the
 * project's method call graph -- the base technique a real
 * interprocedural dataflow framework (an IFDS-style engine, the kind
 * Qodana's own taint analysis is publicly described as using) needs to
 * process a call graph correctly in the presence of recursion/mutual
 * recursion: [compute] returns each SCC as one group, in an order
 * where every SCC a given SCC calls INTO already appears EARLIER in
 * the result -- callees before callers, exactly what a bottom-up
 * interprocedural summary computation needs to iterate over safely.
 *
 * Iterative (a manual explicit stack), not the textbook recursive
 * formulation -- a real project's call graph can be deep enough to
 * overflow the JVM's default call stack with a naive recursive
 * `strongConnect`, and this analysis explicitly promises never to
 * crash on a large graph (see [dev.gaphunter.loginjectioncompanion.detect.ProjectLogTaintAnalyzer.MAX_METHODS]
 * for the separate node-count safety valve).
 *
 * Calls [ProgressManager.checkCanceled] once per traversal step so a
 * large real call graph can't block the read action uncancellably --
 * retrofitted here 2026-09-03 (catalog-wide review found it missing
 * in every copy of this class except
 * `interface-resource-close-divergence-companion`'s).
 */
class TarjanSccComputer<T>(private val graph: Map<T, List<T>>) {

    private var indexCounter = 0
    private val indices = HashMap<T, Int>()
    private val lowlink = HashMap<T, Int>()
    private val onStack = HashSet<T>()
    private val stack = ArrayDeque<T>()
    private val sccs = mutableListOf<List<T>>()

    /** One entry per node still being processed in [strongConnectIterative]: the node itself and how far through its adjacency list we've gotten. */
    private class Frame<T>(val node: T, var childIndex: Int = 0)

    fun compute(): List<List<T>> {
        for (node in graph.keys) {
            if (node !in indices) strongConnectIterative(node)
        }
        return sccs
    }

    private fun strongConnectIterative(start: T) {
        val callStack = ArrayDeque<Frame<T>>()
        callStack.addLast(beginNode(start))

        while (callStack.isNotEmpty()) {
            ProgressManager.checkCanceled()
            val frame = callStack.last()
            val v = frame.node
            val neighbors = graph[v].orEmpty()

            if (frame.childIndex < neighbors.size) {
                val w = neighbors[frame.childIndex]
                frame.childIndex++
                when {
                    w !in indices -> callStack.addLast(beginNode(w))
                    w in onStack -> lowlink[v] = minOf(lowlink.getValue(v), indices.getValue(w))
                    // w is finished and not on the stack -- already in a completed, different SCC; contributes nothing to v's lowlink.
                }
            } else {
                // All neighbors processed -- finalize v, then propagate its lowlink up to whoever called into it.
                if (lowlink.getValue(v) == indices.getValue(v)) {
                    val component = mutableListOf<T>()
                    while (true) {
                        val w = stack.removeLast()
                        onStack -= w
                        component += w
                        if (w == v) break
                    }
                    sccs += component
                }
                callStack.removeLast()
                if (callStack.isNotEmpty()) {
                    val parent = callStack.last().node
                    lowlink[parent] = minOf(lowlink.getValue(parent), lowlink.getValue(v))
                }
            }
        }
    }

    private fun beginNode(v: T): Frame<T> {
        indices[v] = indexCounter
        lowlink[v] = indexCounter
        indexCounter++
        stack.addLast(v)
        onStack += v
        return Frame(v)
    }
}
