#pragma once

#include <QAbstractListModel>
#include <QtQml/qqml.h>
#include <vector>
#include <memory>
#include "types.h"

namespace sys_scan::ui {

struct FindingModelImpl; // namespace-scope PIMPL forward declaration

class FindingModel : public QAbstractListModel {
    Q_OBJECT
    QML_ELEMENT
public:
    enum Roles {
        TitleRole = Qt::UserRole + 1,
        SeverityRole,
        DescriptionRole,
        IdRole
    };

    explicit FindingModel(QObject* parent = nullptr);
    ~FindingModel();

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void clear();

    void loadFindings(std::vector<Finding> findings);

    Q_INVOKABLE void filterBySeverity(int minSeverity);
    Q_INVOKABLE void sortBySeverity(bool descending);

private:
    std::unique_ptr<FindingModelImpl> m_impl;
};

} // namespace sys_scan::ui