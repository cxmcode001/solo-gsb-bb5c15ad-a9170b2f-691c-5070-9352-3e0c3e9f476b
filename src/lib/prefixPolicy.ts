/**
 * 前缀策略校验：对子网分配执行有序 prefix-list。
 *
 * 规则逐行为 `permit|deny CIDR [ge n le m]`：
 * - CIDR 必须对齐网络地址；
 * - 可选范围必须成对写为 `ge n le m`，且满足 CIDR 前缀 ≤ n ≤ m ≤ 32；
 * - 省略范围时仅匹配与 CIDR 同前缀的分配；
 * - 分配须完整位于规则 CIDR 内、且自身前缀落入 [ge, le] 才算命中；
 * - 按首条命中规则决定 permit/deny，全部未命中记为 unmatched。
 *
 * 纯函数、只读：不触碰规划数据与历史栈。
 */
import { Allocation } from './model';
import { Cidr, cidrToString, contains, isAlignedCidr, parseCidr } from './ip';

export type PolicyAction = 'permit' | 'deny';
export type PolicyVerdict = PolicyAction | 'unmatched';

export interface PrefixRule {
  /** 物理行号（从 1 开始，空行也计数，便于定位） */
  lineNo: number;
  action: PolicyAction;
  cidr: Cidr;
  /** 去空白后的原始规则文本（用于报告展示） */
  raw: string;
  ge: number;
  le: number;
}

export interface ParsePolicyResult {
  rules: PrefixRule[];
  /** 逐行错误信息（带行号）；非空时不得生成校验结果 */
  errors: string[];
}

const RULE_HINT = '格式应为 permit|deny CIDR [ge n le m]';

function structureError(lineNo: number, raw: string): string {
  return `第 ${lineNo} 行：无法识别的规则，${RULE_HINT}：${raw}`;
}

/** 逐行解析 prefix-list；空行跳过，任一非空行非法即收集错误（每行至多一条）。 */
export function parsePrefixPolicy(text: string): ParsePolicyResult {
  const rules: PrefixRule[] = [];
  const errors: string[] = [];

  text.split('\n').forEach((rawLine, i) => {
    const lineNo = i + 1;
    const line = rawLine.trim();
    // 空行与以 # 开头的注释行跳过（行号仍计入，便于定位）
    if (!line || line.startsWith('#')) return;
    const tokens = line.split(/\s+/);
    if (tokens.length !== 2 && tokens.length !== 6) {
      errors.push(structureError(lineNo, line));
      return;
    }

    const action = tokens[0].toLowerCase();
    if (action !== 'permit' && action !== 'deny') {
      errors.push(`第 ${lineNo} 行：动作必须为 permit 或 deny：${tokens[0]}`);
      return;
    }

    const cidrToken = tokens[1];
    const cidr = parseCidr(cidrToken);
    if (!cidr) {
      errors.push(`第 ${lineNo} 行：CIDR 非法：${cidrToken}`);
      return;
    }
    if (!isAlignedCidr(cidrToken)) {
      errors.push(
        `第 ${lineNo} 行：CIDR 未对齐网络地址，应为 ${cidrToString(cidr)}：${cidrToken}`,
      );
      return;
    }

    let ge = cidr.prefix;
    let le = cidr.prefix;
    if (tokens.length === 6) {
      if (tokens[2].toLowerCase() !== 'ge' || tokens[4].toLowerCase() !== 'le') {
        errors.push(`第 ${lineNo} 行：可选范围必须同时写为 ge n le m：${line}`);
        return;
      }
      const nToken = tokens[3];
      const mToken = tokens[5];
      const n = /^\d+$/.test(nToken) ? Number(nToken) : NaN;
      const m = /^\d+$/.test(mToken) ? Number(mToken) : NaN;
      if (!Number.isInteger(n) || !Number.isInteger(m) || n < 0 || n > 32 || m < 0 || m > 32) {
        errors.push(`第 ${lineNo} 行：ge/le 必须为 0-32 的整数：${nToken} ${mToken}`);
        return;
      }
      if (!(cidr.prefix <= n && n <= m && m <= 32)) {
        errors.push(
          `第 ${lineNo} 行：范围不合法，需满足 /${cidr.prefix} ≤ ge ${n} ≤ le ${m} ≤ 32`,
        );
        return;
      }
      ge = n;
      le = m;
    }

    rules.push({ lineNo, action, cidr, raw: line, ge, le });
  });

  return { rules, errors };
}

export interface PolicyCheckItem {
  alloc: Allocation;
  verdict: PolicyVerdict;
  /** 首条命中规则；unmatched 时为 null */
  matchedRule: PrefixRule | null;
}

/** 判断单个分配是否命中规则：完整位于规则 CIDR 内，且自身前缀落入 [ge, le]。 */
export function ruleMatches(rule: PrefixRule, cidr: Cidr): boolean {
  return contains(rule.cidr, cidr) && cidr.prefix >= rule.ge && cidr.prefix <= rule.le;
}

/**
 * 按规则顺序对分配执行首条命中匹配。
 * 分配按地址（base）升序处理，保证结果与报告稳定。
 */
export function evaluatePrefixPolicy(
  rules: PrefixRule[],
  allocations: Allocation[],
): PolicyCheckItem[] {
  const sorted = [...allocations].sort((a, b) => {
    const ca = parseCidr(a.cidr);
    const cb = parseCidr(b.cidr);
    return (ca?.base ?? 0) - (cb?.base ?? 0) || a.name.localeCompare(b.name);
  });
  return sorted.map((alloc) => {
    const cidr = parseCidr(alloc.cidr);
    if (cidr) {
      for (const rule of rules) {
        if (ruleMatches(rule, cidr)) {
          return { alloc, verdict: rule.action, matchedRule: rule };
        }
      }
    }
    return { alloc, verdict: 'unmatched', matchedRule: null };
  });
}

const VERDICT_LABEL: Record<PolicyVerdict, string> = {
  permit: 'permit',
  deny: 'deny',
  unmatched: 'unmatched',
};

/** 东亚全角字符按 2 个显示宽度计，用于文本报告对齐。 */
function displayWidth(text: string): number {
  let w = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (
      (code >= 0x1100 && code <= 0x115f) ||
      (code >= 0x2e80 && code <= 0x303e) ||
      (code >= 0x3041 && code <= 0x33ff) ||
      (code >= 0x3400 && code <= 0x4dbf) ||
      (code >= 0x4e00 && code <= 0x9fff) ||
      (code >= 0xa000 && code <= 0xa4cf) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe30 && code <= 0xfe4f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6)
    ) {
      w += 2;
    } else {
      w += 1;
    }
  }
  return w;
}

function padEndDisplay(text: string, width: number): string {
  const gap = width - displayWidth(text);
  return gap > 0 ? text + ' '.repeat(gap) : text;
}

/** 生成可复制的纯文本校验报告。 */
export function formatPolicyReport(items: PolicyCheckItem[], ruleCount: number): string {
  const permit = items.filter((i) => i.verdict === 'permit').length;
  const deny = items.filter((i) => i.verdict === 'deny').length;
  const unmatched = items.filter((i) => i.verdict === 'unmatched').length;

  const lines: string[] = [];
  lines.push('前缀策略校验报告');
  lines.push(
    `规则 ${ruleCount} 条 · 待校验子网 ${items.length} 个 · permit ${permit} · deny ${deny} · unmatched ${unmatched}`,
  );
  lines.push('');

  const nameW = Math.min(
    24,
    Math.max(12, ...items.map((i) => displayWidth(i.alloc.name))),
  );
  const cidrW = Math.max(14, ...items.map((i) => displayWidth(i.alloc.cidr)));

  lines.push(
    `${padEndDisplay('分配', nameW)}  ${padEndDisplay('CIDR', cidrW)}  ${padEndDisplay('结论', 9)}  命中规则`,
  );
  for (const item of items) {
    const hit = item.matchedRule
      ? `第 ${item.matchedRule.lineNo} 行 ${item.matchedRule.raw}`
      : '—';
    lines.push(
      `${padEndDisplay(item.alloc.name, nameW)}  ${padEndDisplay(item.alloc.cidr, cidrW)}  ${padEndDisplay(VERDICT_LABEL[item.verdict], 9)}  ${hit}`,
    );
  }
  return lines.join('\n');
}
