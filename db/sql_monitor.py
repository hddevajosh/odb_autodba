from __future__ import annotations

from odb_autodba.db.connection import fetch_all


def summarize_current_sql(limit: int = 10) -> list[dict]:
    return fetch_all(
        """
        select * from (
            select s.inst_id, s.sid, s.serial# as serial_num, s.username, s.sql_id,
                   q.plan_hash_value, round(q.elapsed_time/1e6,3) as elapsed_s,
                   round(q.cpu_time/1e6,3) as cpu_s, q.buffer_gets, q.disk_reads
            from gv$session s
            join gv$sql q on q.inst_id = s.inst_id and q.sql_id = s.sql_id
            where s.status = 'ACTIVE' and s.username is not null
            order by q.cpu_time desc
        ) where rownum <= :lim
        """,
        {"lim": int(limit)},
    )
