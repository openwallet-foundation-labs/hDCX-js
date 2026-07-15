import SwiftUI
import UIKit

/// The filled/empty PIN dots (turns red on error) — android `PinDots`.
struct PinDots: View {
    let filled: Int
    var total = 6
    var error = false

    var body: some View {
        HStack(spacing: 12) {
            ForEach(0..<total, id: \.self) { i in
                let on = i < filled
                Circle()
                    .fill(on ? tint : .clear)
                    .overlay(Circle().strokeBorder(on ? tint : off, lineWidth: 1.5))
                    .frame(width: 14, height: 14)
            }
        }
    }

    private var tint: Color { error ? WalletTheme.danger : WalletTheme.brand }
    private var off: Color { error ? WalletTheme.danger.opacity(0.4) : Color(hex: 0xC9CFDB) }
}

/// The numeric keypad — digits, backspace, and an optional biometric key in the bottom-left (lock screen).
/// Android `Keypad`.
struct Keypad: View {
    let onDigit: (String) -> Void
    let onDelete: () -> Void
    var onBiometric: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 10) {
            ForEach([["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"]], id: \.self) { row in
                HStack(spacing: 10) {
                    ForEach(row, id: \.self) { d in
                        DigitKey(d) { tap(); onDigit(d) }
                    }
                }
            }
            HStack(spacing: 10) {
                if let onBiometric {
                    IconKey(system: "faceid", tint: WalletTheme.brand) { tap(); onBiometric() }
                } else {
                    Color.clear.frame(maxWidth: .infinity).frame(height: 56)
                }
                DigitKey("0") { tap(); onDigit("0") }
                IconKey(system: "delete.left", tint: WalletTheme.inkBody) { tap(); onDelete() }
            }
        }
        .frame(maxWidth: 300)
    }

    private func tap() { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
}

private struct DigitKey: View {
    let digit: String
    let action: () -> Void
    init(_ digit: String, action: @escaping () -> Void) { self.digit = digit; self.action = action }

    var body: some View {
        Button(action: action) {
            Text(digit)
                .font(.custom("Manrope", size: 21).weight(.bold))
                .foregroundStyle(WalletTheme.ink)
                .frame(maxWidth: .infinity).frame(height: 56)
                .background(WalletTheme.card, in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(WalletTheme.cardBorderStrong, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }
}

private struct IconKey: View {
    let system: String
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: system)
                .font(.system(size: 22))
                .foregroundStyle(tint)
                .frame(maxWidth: .infinity).frame(height: 56)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
