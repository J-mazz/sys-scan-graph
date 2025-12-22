#pragma once

#include <QString>
#include <QObject>
#include <compare>

namespace sys_scan::ui {

// Severity Enum with QML exposure
struct Severity {
    Q_GADGET
public:
    enum Value {
        Info,
        Low,
        Medium,
        High,
        Critical
    };
    Q_ENUM(Value)
};

struct Finding {
    Q_GADGET
    Q_PROPERTY(QString id MEMBER id CONSTANT)
    Q_PROPERTY(QString title MEMBER title CONSTANT)
    Q_PROPERTY(QString description MEMBER description CONSTANT)
    Q_PROPERTY(Severity::Value severity MEMBER severity CONSTANT)
    Q_PROPERTY(bool correlated MEMBER correlated CONSTANT)

public:
    QString id;
    QString title;
    QString description;
    Severity::Value severity{};
    bool correlated{false};


    // Custom three-way comparison; QString doesn't provide <=> directly
    auto operator<=>(const Finding& other) const noexcept -> std::strong_ordering {
        if (auto cmp = static_cast<int>(severity) <=> static_cast<int>(other.severity); cmp != 0)
            return cmp;

        int r = id.compare(other.id, Qt::CaseSensitive);
        if (r < 0) return std::strong_ordering::less;
        if (r > 0) return std::strong_ordering::greater;

        r = title.compare(other.title, Qt::CaseSensitive);
        if (r < 0) return std::strong_ordering::less;
        if (r > 0) return std::strong_ordering::greater;

        r = description.compare(other.description, Qt::CaseSensitive);
        if (r < 0) return std::strong_ordering::less;
        if (r > 0) return std::strong_ordering::greater;

        return std::strong_ordering::equal;
    }
};

struct ParseError {
    QString message;
    std::size_t offset{};
};

} // namespace sys_scan::ui
