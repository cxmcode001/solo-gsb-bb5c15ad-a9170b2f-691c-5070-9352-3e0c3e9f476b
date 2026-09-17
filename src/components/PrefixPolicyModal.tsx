import { useState } from 'react';
import { Allocation } from '../lib/model';
import {
  PrefixRule,
  PolicyCheckItem,
  formatPolicyReport,
  parsePrefixPolicy,
  evaluatePrefixPolicy,
} from '../lib/prefixPolicy';

interface Props {
  /** 仅传入 subnet 类型的分配；校验只读，不修改规划与历史 */
  allocations: Allocation[];
  onClose: () => void;
}

const PLACEHOLDER = [
  '# 每行一条，按顺序首条命中',
  'permit 10.0.0.0/8 ge 16 le 24',
  'deny 10.1.0.0/16',
  'permit 192.168.0.0/16 le 24',
].join('\n');

const VERDICT_TEXT = {
  permit: '允许 (permit)',
  deny: '拒绝 (deny)',
  unmatched: '未命中 (unmatched)',
} as const;

/**
 * 前缀策略校验弹窗：对当前全部子网分配执行有序 prefix-list。
 * 纯本地只读计算：不修改规划、不产生历史记录。
 */
export default function PrefixPolicyModal({ allocations, onClose }: Props) {
  const [text, setText] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [items, setItems] = useState<PolicyCheckItem[] | null>(null);
  const [rules, setRules] = useState<PrefixRule[]>([]);
  const [copied, setCopied] = useState(false);

  const run = () => {
    const hasRule = text
      .split('\n')
      .some((l) => l.trim() && !l.trim().startsWith('#'));
    if (!hasRule) {
      setErrors(['请至少输入一条规则（格式：permit|deny CIDR [ge n le m]）']);
      setItems(null);
      setRules([]);
      setCopied(false);
      return;
    }
    const parsed = parsePrefixPolicy(text);
    setErrors(parsed.errors);
    setCopied(false);
    if (parsed.errors.length > 0) {
      // 任一非空行非法时不生成结果
      setItems(null);
      setRules([]);
      return;
    }
    setRules(parsed.rules);
    setItems(evaluatePrefixPolicy(parsed.rules, allocations));
  };

  const report = items ? formatPolicyReport(items, rules.length) : '';
  const permitN = items ? items.filter((i) => i.verdict === 'permit').length : 0;
  const denyN = items ? items.filter((i) => i.verdict === 'deny').length : 0;
  const unmatchedN = items ? items.filter((i) => i.verdict === 'unmatched').length : 0;

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(report);
    } catch {
      // 剪贴板 API 不可用（如非安全上下文）时回退
      const ta = document.createElement('textarea');
      ta.value = report;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <h3>前缀策略校验</h3>
        <p className="muted">
          对当前 <strong>{allocations.length}</strong> 个<strong>子网</strong>分配按规则顺序逐条匹配（保留段不参与）。
          规则格式：<code>permit|deny CIDR [ge n le m]</code>；CIDR 必须对齐，范围必须成对出现，
          且满足 CIDR 前缀 ≤ n ≤ m ≤ 32；省略范围时仅匹配同前缀。分配须完整位于规则 CIDR
          且自身前缀落入范围才命中，按<strong>首条命中</strong>判定，全部未命中记为 unmatched。
          本校验为只读操作，不修改规划、不进入撤销历史。
        </p>

        <label className="field">
          <span>前缀列表（每行一条，空行与 # 开头行会被忽略为空行）</span>
          <textarea
            autoFocus
            rows={6}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
          />
        </label>

        {errors.length > 0 && (
          <ul className="errors">
            {errors.map((er, i) => (
              <li key={i}>{er}</li>
            ))}
          </ul>
        )}

        {items && (
          <div className="dhcp-result">
            <div className="dhcp-result-head">
              <span>
                permit {permitN} · deny {denyN} · unmatched {unmatchedN}
              </span>
              <button className="btn small" onClick={() => void copyReport()}>
                {copied ? '已复制 ✓' : '复制文本报告'}
              </button>
            </div>
            {items.length === 0 ? (
              <p className="muted">当前没有子网分配，无可校验对象。</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>分配</th>
                      <th>CIDR</th>
                      <th>结论</th>
                      <th>命中行</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.alloc.id} className={`policy-${item.verdict}`}>
                        <td><strong>{item.alloc.name}</strong></td>
                        <td><code>{item.alloc.cidr}</code></td>
                        <td>
                          <span className={`badge policy-${item.verdict}`}>
                            {VERDICT_TEXT[item.verdict]}
                          </span>
                        </td>
                        <td>
                          {item.matchedRule ? (
                            <span>
                              第 {item.matchedRule.lineNo} 行{' '}
                              <code>{item.matchedRule.raw}</code>
                            </span>
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <textarea
              readOnly
              rows={Math.min(Math.max(items.length + 3, 6), 14)}
              value={report}
            />
          </div>
        )}

        <div className="modal-actions">
          <button className="btn" onClick={onClose}>
            关闭
          </button>
          <button className="btn primary" onClick={run}>
            执行校验
          </button>
        </div>
      </div>
    </div>
  );
}
