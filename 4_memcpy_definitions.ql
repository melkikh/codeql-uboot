import cpp

from Function f
where f.getName() = "memcpy"
select f, f.getLocation(), "memcpy function"