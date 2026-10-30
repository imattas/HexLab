# Shared analysis pool

`AnalysisPool` runs immutable analysis work for multiple open document sessions.
`PoolLimits::max_sessions` bounds registered sessions, and `max_workers` sets the
number of jobs that may run concurrently across those sessions. The default is
two workers; callers can select from one to sixteen when constructing the pool.
Values outside those limits are rejected.

Each session still has at most one active job and one replaceable pending job.
The worker limit is pool-wide, so increasing it lets independent documents
analyze concurrently without allowing two writes or analyses to overlap inside
one session. Foreground jobs retain priority over normal jobs, with submission
order breaking ties. Cancellation, session epochs, and completion tickets still
gate publication when work finishes after a newer request.

The worker count is fixed for the lifetime of the pool. To change it, create a
new pool and activate the desired sessions on that pool; an existing pool does
not resize its worker threads.
