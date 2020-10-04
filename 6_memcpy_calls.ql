import cpp

from FunctionCall fc, Function f
where
    // f.getName() = "memcpy" and
    // fc.getTarget() = f and
    fc.getTarget().getName() = "memcpy"
select fc, "memcpy function call"
