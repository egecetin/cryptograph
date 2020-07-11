#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "filer.h"

#include <QMainWindow>
#include <QFileDialog>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
		
public:
    MainWindow(QWidget *parent = nullptr);
	ERR_STATUS processFile(QString &password);
    ~MainWindow();

	Q_SLOT void srcPathClicked();
	Q_SLOT void destPathClicked();
	Q_SLOT void compressionMethod(int id);
	Q_SLOT void encryptionMethod(int id);
	Q_SLOT void hashMethod(int id);
	Q_SLOT void convert();

private:
    Ui::MainWindow *ui;
	std::string pathSrc, pathDest;
	ege::COMPRESSION_METHOD comp;
	ege::CRYPTO_METHOD crypt;
	IppHashAlgId hash;

	void setPath(int id);

};
#endif // MAINWINDOW_H
