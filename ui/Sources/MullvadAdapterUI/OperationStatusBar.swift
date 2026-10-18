import SwiftUI

/// Always occupies the same space, including while idle. Details are presented
/// outside document layout so long errors never move the user's click target.
struct OperationStatusBar: View {
    @ObservedObject var model: AdapterViewModel
    @State private var showDetails = false

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Image(systemName: model.connectionError == nil ? "info.circle" : "exclamationmark.triangle")
                    .opacity(model.isBusy || model.isSpeedTesting || model.isExportingReport ? 0 : 1)
                if model.isBusy || model.isSpeedTesting || model.isExportingReport {
                    ProgressView().controlSize(.small)
                }
            }.frame(width: 20)

            VStack(alignment: .leading, spacing: 3) {
                Text(model.feedbackSummary).font(.callout).lineLimit(1).truncationMode(.middle)
                Text(model.isCancellingSpeedTest ? "正在等待后台结束当前探针并清理" : "操作进度与结果 · 完整信息可查看详情")
                    .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Button { model.cancelSpeedTest() } label: {
                Text(model.isCancellingSpeedTest ? "正在停止" : "停止测速")
                    .frame(width: 80, height: 36).contentShape(Rectangle())
            }
            .disabled(!model.canCancelSpeedTest || model.isCancellingSpeedTest)
            Button { showDetails.toggle() } label: {
                Text("详情").padding(.horizontal, 10).padding(.vertical, 8).contentShape(Rectangle())
            }
            .popover(isPresented: $showDetails) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(model.lastQuickPingBatchLabel.map { "\($0) · 快速 Ping 明细" } ?? "操作与提示详情").font(.headline)
                            Text("每条结果都包含目标地址、绑定接口、耗时、命令返回和时间。ICMP 无回复只表示对方没有回应 Ping。")
                                .font(.caption).foregroundStyle(.secondary)
                            ForEach(Array(model.feedbackDetails.enumerated()), id: \.offset) { _, message in
                                Text(message).textSelection(.enabled)
                                Divider()
                            }
                            HStack {
                                Button("复制详情") {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(model.feedbackDetails.joined(separator: "\n\n"), forType: .string)
                                }
                                Spacer()
                                Button("清除已结束的提示") { model.clearFeedback() }
                            }
                        }.padding(16)
                    }.frame(width: 480, height: 340)
                }
        }
        .padding(.horizontal, 14)
        .frame(height: 64)
        .background(Color(nsColor: .controlBackgroundColor))
        .accessibilityIdentifier("operation-status-bar")
    }
}
