-- ============================================================
-- 论文工单管理 · 权限设置
--
-- 用途：
--   - 管理端（admin.html）：只有登录的你能读写 orders 表
--   - 公开展示端（index.html）：任何人都能只读一个脱敏视图，
--     看不到客户姓名、金额、收款记录、备注等敏感字段
--
-- 使用方法：
--   1. 打开 Supabase 项目 → SQL Editor → New query
--   2. 下面第 3 步已经填好了 owner 邮箱 2638548180@qq.com
--      （必须和你在 admin.html 里登录用的邮箱一致，如果之后换了
--      登录邮箱，记得回来改这里再重新执行一次）
--   3. 整段粘贴执行一次即可，可以重复执行（用了 if exists / or replace）
--
-- 执行前提：
--   - 需要先在 Supabase 后台创建你自己的登录账号：
--     Authentication → Users → Add user，填邮箱+密码，
--     Auto Confirm User 打勾（不用发验证邮件）
--   - 建议同时去 Authentication → Providers → Email，
--     把 "Allow new users to sign up" 关掉，防止陌生人自己注册账号
--     （下面第 3 步的策略已经按邮箱锁死了，这一步是双保险）
-- ============================================================

-- 1. 给 orders 表开启行级安全（RLS）。
--    开启后，默认所有角色都拿不到任何一行数据，
--    除非下面显式为某个角色建了策略——这正是我们要的效果。
alter table public.orders enable row level security;

-- 2. 清理旧策略（如果之前跑过这个脚本或手动建过策略）
drop policy if exists "orders_owner_full_access" on public.orders;
drop policy if exists "orders_select_authenticated" on public.orders;
drop policy if exists "orders_write_authenticated" on public.orders;

-- 3. 只有你（指定邮箱的登录账号）能读写 orders 表的所有行。
--    这里没有给 anon（未登录访客）任何策略，所以他们对 orders 表
--    的直接访问会被 RLS 拒绝——哪怕拿着 anon key 也拿不到数据。
create policy "orders_owner_full_access"
  on public.orders
  for all
  to authenticated
  using (auth.jwt() ->> 'email' = '2638548180@qq.com')
  with check (auth.jwt() ->> 'email' = '2638548180@qq.com');

-- 4. 建一个脱敏的公开视图，只暴露非敏感字段：
--    课题、服务状态、进度阶段+日期（去掉进度备注 note，因为
--    备注里可能写了客户相关信息）、更新时间。
--    不包含：customer_name / group_name / amount / channel /
--            payments / notes。
create or replace view public.orders_public as
select
  id,
  topic,
  service_status,
  (
    select coalesce(
      jsonb_agg(jsonb_build_object('stage', elem->>'stage', 'date', elem->>'date')),
      '[]'::jsonb
    )
    from jsonb_array_elements(coalesce(progresses, '[]'::jsonb)) as elem
  ) as progresses,
  updated_at
from public.orders;

-- 5. 只允许匿名角色只读这个脱敏视图（不给写权限）。
--    视图默认以创建者（表的所有者）身份查询底层表，
--    所以即使 orders 表本身对 anon 关闭了 RLS 访问，
--    这个视图依然能正常把脱敏后的数据吐给 anon。
grant select on public.orders_public to anon;

-- 6. 兜底：确保 anon 角色对 orders 原表没有任何直接授权
--    （即使之前在 Table Editor 里默认开了权限，这里也收回）。
revoke all on public.orders from anon;
