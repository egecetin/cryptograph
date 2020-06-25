#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "filer.h"

#include <QMainWindow>
#include <QFileDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
		
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

	Q_SLOT void srcPathClicked();
	Q_SLOT void destPathClicked();
	Q_SLOT void compressionMethod(int id);
	Q_SLOT void encryptionMethod(int id);
	void convert();

private:
    Ui::MainWindow *ui;
	std::string pathSrc, pathDest;
	ege::COMPRESSION_METHOD comp;
	ege::CRYPTO_METHOD crypt;

	void setPath(int id);

};
#endif // MAINWINDOW_H
