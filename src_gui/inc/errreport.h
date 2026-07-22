//
// Created by Tofu on 2025/5/15.
//

#ifndef ERRREPORT_H
#define ERRREPORT_H

#include <QMutex>
#include <QObject>
#include <utility>

class ErrorReporter: public QObject
{
    Q_OBJECT
    static ErrorReporter _instance;
    static QMetaObject::Connection connection;
public:
    static constexpr char 严重[] = "_(´ཀ`」 ∠)_";
    static constexpr char 警告[] = "危";
    struct ErrorInfo {
        QString level;
        QString msg;
    };

    static ErrorReporter* instance();
    static void receive(const ErrorInfo& einfo);
    static void receive(QString level, QString msg)
    {
        receive({std::move(level), std::move(msg)});
    }
    static void silent()
    {
        if (connection)
            QObject::disconnect(connection);
    }
    static void verbose()
    {
        connection = QObject::connect(instance(), &ErrorReporter::report,  &ErrorReporter::showError);
    }

signals:
    void report(const ErrorInfo& einfo);
private:
explicit
    ErrorReporter(QObject *parent = nullptr);
private slots:
    static void showError(const ErrorInfo& einf);
};
#endif
