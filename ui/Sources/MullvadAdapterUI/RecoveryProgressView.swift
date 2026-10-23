import SwiftUI

// A fixed-height home surface: background progress never shifts the city cards.
struct RecoveryProgressView: View {
    @ObservedObject var model: AdapterViewModel

    private var recovery: RecoveryStatus? { model.status?.recovery }
    private var stale: Bool { model.connectionError != nil }
    private var offline: Bool { model.status?.localNetwork?.paused == true }

    var body: some View {
        AppCard("连接恢复") {
            HStack(spacing: 8) {
                Image(systemName: stale ? "clock.badge.exclamationmark" : recovery?.running == true ? "arrow.triangle.2.circlepath" : "shield.lefthalf.filled")
                    .foregroundStyle(stale ? Color.orange : Color.accentColor)
                Text(stale ? "最后记录的恢复进度" : offline ? "本机断网，暂停恢复" : recovery?.title ?? "自动恢复待命")
                    .font(.headline).lineLimit(1)
                Spacer(minLength: 0)
                if recovery?.running == true && !stale && !offline { ProgressView().controlSize(.small) }
            }
            Text(recovery?.target ?? model.status?.activeRelay ?? "等待选择城市和节点")
                .font(.system(.caption, design: .monospaced)).lineLimit(1).textSelection(.enabled)
            Text(recovery?.timing ?? "原入口重试 → 备用 SS → 最多 4 个同城节点")
                .font(.caption).foregroundStyle(.secondary).lineLimit(2).frame(height: 30, alignment: .top)
            Text(stale ? "状态读取暂缓；以下是上次记录，不能据此判断通断。恢复新状态后可操作。" : offline ? "联网稳定后先验证原路径，不把本机断网记成节点失败。" : recovery?.message ?? "连续两次确认数据通道失败后，才启动恢复。")
                .font(.subheadline).lineLimit(2).frame(height: 34, alignment: .top)
            Text(recovery?.nextStep ?? "原入口清理后立即重试，再分别等待 1 秒、5 秒重试；同城仍失败则有限冷却再试。Mac 尚无链式保底。")
                .font(.caption).foregroundStyle(.secondary).lineLimit(2).frame(height: 30, alignment: .top)
            HStack(spacing: 8) {
                recoveryButton("重试原节点", action: "retry-current")
                recoveryButton("重新自动恢复", action: "retry-round")
                Spacer(minLength: 0)
                Button { model.controlRecovery("stop") } label: {
                    Text("停止恢复").padding(.horizontal, 7).padding(.vertical, 5).contentShape(Rectangle())
                }.disabled(stale || model.isRecoveryControlPending || recovery?.running != true)
            }.controlSize(.small)
        }
        .accessibilityIdentifier("home-recovery-progress")
    }

    private func recoveryButton(_ title: String, action: String) -> some View {
        Button { model.controlRecovery(action) } label: {
            Text(title).padding(.horizontal, 7).padding(.vertical, 5).contentShape(Rectangle())
        }.disabled(stale || offline || model.isBusy || model.isSpeedTesting || model.isRecoveryControlPending || model.status?.activeRelay == nil)
    }
}
