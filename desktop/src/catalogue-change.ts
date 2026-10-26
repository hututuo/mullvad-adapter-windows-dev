import type { CatalogueChanges } from "./app-api";
export function catalogueSummary(report: CatalogueChanges | null | undefined): string {
  if (!report) return "后台尚未提供目录对比";
  if (!report.baseline_available) return "已取得目录，首次记录暂无对照";
  if (report.catalogue_changed === false) return "检查完成，目录没有变化";
  return `新增 ${report.added_count} · 移除 ${report.removed_count} · 变更 ${report.changed_count} 个节点`;
}
export function catalogueRelayState(state: string): string {
  return ({unchanged:"连接参数没有变化",changed:"连接参数有变化",added:"官方目录新增此节点",removed:"官方目录已移除此节点",unavailable:"当前目录中没有此节点",no_baseline:"首次记录，没有旧目录可对照",unselected:"检查时尚无选定节点"} as Record<string,string>)[state] ?? "无法确认变化";
}
