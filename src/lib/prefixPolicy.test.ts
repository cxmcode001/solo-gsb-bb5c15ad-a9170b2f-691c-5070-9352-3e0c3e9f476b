import { describe, expect, it } from 'vitest';
import { Allocation } from './model';
import {
  evaluatePrefixPolicy,
  formatPolicyReport,
  parsePrefixPolicy,
  ruleMatches,
} from './prefixPolicy';
import { parseCidr } from './ip';

const mk = (name: string, cidr: string, kind: Allocation['kind'] = 'subnet'): Allocation => ({
  id: `${name}-${cidr}`,
  name,
  kind,
  prefix: parseCidr(cidr)!.prefix,
  cidr,
});

const rulesOf = (text: string) => parsePrefixPolicy(text).rules;

describe('prefix-list 规则解析', () => {
  it('省略范围时仅匹配同前缀（ge=le=CIDR 前缀）', () => {
    const { rules, errors } = parsePrefixPolicy('permit 10.0.0.0/8\n');
    expect(errors).toEqual([]);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ action: 'permit', ge: 8, le: 8, lineNo: 1 });
    expect(rules[0].cidr.prefix).toBe(8);
  });

  it('解析成对的 ge n le m', () => {
    const { rules, errors } = parsePrefixPolicy('DENY 10.0.0.0/8 GE 16 LE 24');
    expect(errors).toEqual([]);
    expect(rules[0]).toMatchObject({ action: 'deny', ge: 16, le: 24 });
  });

  it('允许边界相等：前缀=n=m', () => {
    const { rules, errors } = parsePrefixPolicy('permit 10.1.0.0/16 ge 16 le 16');
    expect(errors).toEqual([]);
    expect(rules[0]).toMatchObject({ ge: 16, le: 16 });
  });

  it('空行与 # 注释行跳过，但物理行号仍计数', () => {
    const text = '\n  \n# 这是注释\npermit 10.0.0.0/8\n\n';
    const { rules } = parsePrefixPolicy(text);
    expect(rules).toHaveLength(1);
    expect(rules[0].lineNo).toBe(4);
  });

  it('原始文本去空白保留，用于报告展示', () => {
    const { rules } = parsePrefixPolicy('  permit   10.0.0.0/8   ge 16 le 24  ');
    expect(rules[0].raw).toBe('permit   10.0.0.0/8   ge 16 le 24');
  });

  it('逐行收集错误：非法动作、非法 CIDR、未对齐 CIDR', () => {
    const text = ['allow 10.0.0.0/8', 'permit 10.0.0.0/33', 'deny 10.0.0.1/24'].join('\n');
    const { rules, errors } = parsePrefixPolicy(text);
    expect(rules).toEqual([]);
    expect(errors).toHaveLength(3);
    expect(errors[0]).toContain('第 1 行');
    expect(errors[0]).toContain('permit 或 deny');
    expect(errors[1]).toContain('第 2 行');
    expect(errors[2]).toContain('未对齐');
    expect(errors[2]).toContain('10.0.0.1');
  });

  it('范围必须成对：只写 ge 或只写 le 均非法', () => {
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 16').errors[0]).toContain('第 1 行');
    expect(parsePrefixPolicy('permit 10.0.0.0/8 le 24').errors[0]).toContain('第 1 行');
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 16 le 24 extra').errors[0]).toContain(
      '第 1 行',
    );
  });

  it('范围关键字位置错误', () => {
    const { errors } = parsePrefixPolicy('permit 10.0.0.0/8 le 16 ge 24');
    expect(errors[0]).toContain('ge n le m');
  });

  it('ge/le 必须为 0-32 整数', () => {
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 16 le x').errors[0]).toContain('整数');
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge -1 le 24').errors[0]).toContain('第 1 行');
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 16 le 33').errors[0]).toContain('整数');
  });

  it('须满足 CIDR 前缀 ≤ ge ≤ le ≤ 32', () => {
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 7 le 24').errors[0]).toContain('范围不合法');
    expect(parsePrefixPolicy('permit 10.0.0.0/8 ge 24 le 16').errors[0]).toContain('范围不合法');
  });

  it('任一非空行非法时解析结果带错误，合法行仍被收集（由调用方决定不生成结果）', () => {
    const text = 'permit 10.0.0.0/8\nbroken line here\npermit 192.168.0.0/16';
    const { rules, errors } = parsePrefixPolicy(text);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('第 2 行');
    expect(rules.map((r) => r.lineNo)).toEqual([1, 3]);
  });
});

describe('规则命中判定', () => {
  it('省略范围时仅同前缀命中（即便完整包含也不命中）', () => {
    const r = rulesOf('permit 10.0.0.0/8')[0];
    expect(ruleMatches(r, parseCidr('10.0.0.0/8')!)).toBe(true);
    expect(ruleMatches(r, parseCidr('10.1.0.0/16')!)).toBe(false);
    expect(ruleMatches(r, parseCidr('0.0.0.0/0')!)).toBe(false);
  });

  it('范围匹配：前缀落入 [ge, le] 且完整位于规则 CIDR', () => {
    const r = rulesOf('permit 10.0.0.0/8 ge 16 le 24')[0];
    expect(ruleMatches(r, parseCidr('10.1.0.0/16')!)).toBe(true);
    expect(ruleMatches(r, parseCidr('10.1.1.0/24')!)).toBe(true);
    expect(ruleMatches(r, parseCidr('10.0.0.0/8')!)).toBe(false); // 前缀 8 < ge
    expect(ruleMatches(r, parseCidr('10.1.0.0/25')!)).toBe(false); // 前缀 25 > le
  });

  it('前缀在范围内但未完整位于规则 CIDR 时不命中', () => {
    const r = rulesOf('permit 10.1.0.0/16 ge 16 le 24')[0];
    // 与规则块相交但不被完整包含
    expect(ruleMatches(r, parseCidr('10.0.0.0/16')!)).toBe(false);
    expect(ruleMatches(r, parseCidr('10.0.128.0/17')!)).toBe(false);
  });
});

describe('有序策略评估', () => {
  const allocs = [
    mk('核心', '10.0.0.0/16'),
    mk('DC-A', '10.1.0.0/18'),
    mk('DC-B', '10.1.64.0/18'),
    mk('办公有线', '192.168.0.0/22'),
    mk('访客', '192.168.8.0/24'),
  ];

  it('首条命中决定 permit/deny，未命中记 unmatched', () => {
    const text = [
      'deny 10.1.0.0/16 ge 18 le 32',
      'permit 10.0.0.0/8 ge 16 le 24',
      'permit 192.168.0.0/16 ge 16 le 22',
    ].join('\n');
    const items = evaluatePrefixPolicy(rulesOf(text), allocs);
    const byName = Object.fromEntries(items.map((i) => [i.alloc.name, i]));
    expect(byName['核心'].verdict).toBe('permit');
    expect(byName['核心'].matchedRule?.lineNo).toBe(2);
    expect(byName['DC-A'].verdict).toBe('deny');
    expect(byName['DC-A'].matchedRule?.lineNo).toBe(1);
    expect(byName['DC-B'].verdict).toBe('deny');
    expect(byName['办公有线'].verdict).toBe('permit');
    expect(byName['访客'].verdict).toBe('unmatched');
    expect(byName['访客'].matchedRule).toBeNull();
  });

  it('结果按地址升序，而非输入顺序', () => {
    const items = evaluatePrefixPolicy(rulesOf('permit 0.0.0.0/0 ge 0 le 32'), [
      mk('后', '192.168.0.0/24'),
      mk('前', '10.0.0.0/24'),
    ]);
    expect(items.map((i) => i.alloc.name)).toEqual(['前', '后']);
  });

  it('空规则集时全部 unmatched', () => {
    const items = evaluatePrefixPolicy([], allocs);
    expect(items.every((i) => i.verdict === 'unmatched')).toBe(true);
  });
});

describe('文本报告', () => {
  it('包含表头、统计与每条分配的结论和命中行', () => {
    const text = 'deny 10.1.0.0/16 ge 18 le 32\npermit 10.0.0.0/8 ge 16 le 24';
    const allocs = [mk('数据中心', '10.1.0.0/18'), mk('核心交换', '10.0.0.0/16')];
    const items = evaluatePrefixPolicy(rulesOf(text), allocs);
    const report = formatPolicyReport(items, 2);
    expect(report).toContain('前缀策略校验报告');
    expect(report).toContain('规则 2 条');
    expect(report).toContain('待校验子网 2 个');
    expect(report).toContain('permit 1');
    expect(report).toContain('deny 1');
    expect(report).toContain('数据中心');
    expect(report).toContain('deny');
    expect(report).toContain('第 1 行 deny 10.1.0.0/16 ge 18 le 32');
    expect(report).toContain('第 2 行 permit 10.0.0.0/8 ge 16 le 24');
  });

  it('unmatched 在报告中显示为 —', () => {
    const items = evaluatePrefixPolicy([], [mk('访客', '192.168.8.0/24')]);
    const report = formatPolicyReport(items, 0);
    expect(report).toContain('unmatched');
    expect(report).toMatch(/unmatched\s+—/);
  });
});
