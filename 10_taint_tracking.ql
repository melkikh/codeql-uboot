/* 
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(
            MacroInvocation mi | 
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") |
            this = mi.getExpr()
        )
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "Taint tracking analysis from Network byte swap fuctions to memcpy" }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap 
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(
            FunctionCall call |
            sink.asExpr() = call.getArgument(2) |
            call.getTarget().getName() = "memcpy"
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "network byte swap flows to memcpy"