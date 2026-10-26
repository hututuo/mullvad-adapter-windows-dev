import SwiftUI

struct CatalogueChangesView: View {
    let metadata: MetadataStatus?
    let activeRelay: String?
    @Environment(\.dismiss) private var dismiss
    @State private var expandedRelays: Set<Int> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("官方目录更新内容").font(.title2.bold())
                    Text("对照上一次有效目录；不会因为点击更新就重建连接。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
            }.padding(20)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let error = metadata?.error {
                        Label("本次获取失败，继续使用上次有效目录", systemImage: "exclamationmark.triangle")
                        Text(error).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        Text("下面如有对比结果，属于最近一次成功检查。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let change = metadata?.changeSummary {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(change.summary).font(.headline)
                            Text("检查时间：\(displayTime(change.checkedAt))").font(.caption).foregroundStyle(.secondary)
                            if change.catalogueChanged == true && change.addedCount + change.removedCount + change.changedCount == 0 {
                                Text("节点本身没有增减或修改；变化来自共享端口或其他目录参数。")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("检查时使用的节点").font(.headline)
                                Text(change.currentRelay.relay ?? "未选定").font(.body.monospaced())
                                Text(change.currentRelay.stateTitle)
                                    .foregroundStyle(change.currentRelay.state == "unchanged" ? Color.secondary : Color.primary)
                                if let activeRelay, let checkedRelay = change.currentRelay.relay, activeRelay != checkedRelay {
                                    Text("当前已切换到 \(activeRelay)，以上对比针对检查时的 \(checkedRelay)。")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                if let after = change.currentRelay.ssAfterCount {
                                    Text("SS 地址／端口组合：\(change.currentRelay.ssBeforeCount.map(String.init) ?? "无旧记录") → \(after)")
                                        .font(.caption.monospaced())
                                }
                                if change.currentRelay.state == "unchanged" {
                                    Text("专用 SS 地址、主地址 SS 端口、IPv4／IPv6、公钥和官方可用状态均未变化。")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                fields(change.currentRelay.fields)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                        if !change.sharedChanges.isEmpty {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("共享目录参数").font(.headline)
                                fields(change.sharedChanges)
                            }
                        }
                        if !change.changedRelays.isEmpty {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("变化的节点").font(.headline)
                                ForEach(change.changedRelays.indices, id: \.self) { index in
                                    let relay = change.changedRelays[index]
                                    VStack(alignment: .leading, spacing: 4) {
                                        Button {
                                            if !expandedRelays.insert(index).inserted { expandedRelays.remove(index) }
                                        } label: {
                                            HStack {
                                                Image(systemName: expandedRelays.contains(index) ? "chevron.down" : "chevron.right")
                                                Text(relay.relay ?? "—").font(.body.monospaced())
                                                Spacer()
                                                Text(relay.stateTitle).font(.caption).foregroundStyle(.secondary)
                                            }.frame(maxWidth: .infinity, minHeight: 28).contentShape(Rectangle())
                                        }.buttonStyle(.plain)
                                        if expandedRelays.contains(index) {
                                            if relay.fields.isEmpty {
                                                Text(relay.stateTitle).font(.caption).padding(.vertical, 6)
                                            } else { fields(relay.fields).padding(.vertical, 6) }
                                        }
                                    }
                                }
                                if change.truncatedCount > 0 {
                                    Text("另有 \(change.truncatedCount) 个节点变化；此处最多列出 20 个，检查时使用的节点优先。")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        Divider()
                        Text("目录没变，只能排除“官方公布的这些连接参数发生变化”；不能据此排除节点服务波动或网络路径问题。SS 组合数量也不代表这些入口都可用。")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("暂无目录对比结果").font(.headline)
                        Text("请点击“更新官方目录”。首次取得目录只能建立基线；旧版后台也可能尚未提供对比信息。")
                            .foregroundStyle(.secondary)
                    }
                    if metadata?.cacheError != nil {
                        Text("新目录已在内存生效，但本地缓存保存失败；重启后可能仍读取旧缓存。")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            }
        }.frame(width: 700, height: 580)
    }

    private func fields(_ values: [CatalogueFieldChange]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(values.indices, id: \.self) { index in
                let field = values[index]
                VStack(alignment: .leading, spacing: 4) {
                    Text(field.label).font(.subheadline.bold())
                    if let added = field.addedCount, let removed = field.removedCount {
                        Text("新增 \(added) · 移除 \(removed)").font(.caption)
                        if let items = field.added, !items.isEmpty {
                            Text("新增：\(items.joined(separator: "、"))").font(.caption.monospaced()).textSelection(.enabled)
                        }
                        if let items = field.removed, !items.isEmpty {
                            Text("移除：\(items.joined(separator: "、"))").font(.caption.monospaced()).textSelection(.enabled)
                        }
                        if added > (field.added?.count ?? 0) || removed > (field.removed?.count ?? 0) {
                            Text("明细各最多显示 12 项。").font(.caption).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("之前：\(field.before)").font(.caption.monospaced()).textSelection(.enabled)
                        Text("现在：\(field.after)").font(.caption.monospaced()).textSelection(.enabled)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func displayTime(_ value: String) -> String {
        ISO8601DateFormatter().date(from: value)?.formatted(date: .abbreviated, time: .standard) ?? value
    }
}
