#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

void MainWindow::srcPathClicked()
{
	this->setPath(1);
}

void MainWindow::destPathClicked()
{
	this->setPath(2);
}

void MainWindow::compressionMethod(int id)
{
	this->comp = static_cast<ege::COMPRESSION_METHOD>(id);
}

void MainWindow::encryptionMethod(int id)
{
	this->crypt = static_cast<ege::CRYPTO_METHOD>(id);
}

void MainWindow::hashMethod(int id)
{
	this->hash = static_cast<IppHashAlgId>(id);
}

void MainWindow::convert()
{
	ERR_STATUS status = NO_ERROR;
	
	// Check files
	if (!(this->pathDest.length() && this->pathSrc.length())) {
		QMessageBox::critical(this, tr("Error"), tr("Please select the source and destination paths."));
		return;
	}
	if (this->crypt == ege::CRYPTO_METHOD::RSA || this->crypt == ege::CRYPTO_METHOD::ECCP) {
		QMessageBox::critical(this, tr(""), tr("RSA and ECCP encryption methods are not implemented yet"));
		return;
	}
	if (this->comp == ege::COMPRESSION_METHOD::ZLIB_FAST || this->comp == ege::COMPRESSION_METHOD::ZLIB_AVERAGE
		|| this->comp == ege::COMPRESSION_METHOD::ZLIB_SLOW || this->comp == ege::COMPRESSION_METHOD::LZ4_HC) {
		QMessageBox::critical(this, tr(""), tr("ZLIB and LZ4 High Compression methods are not implemented yet"));
		return;
	}

	// Ask for password
	QString text; 
	bool flag = false;
	while (!flag)
	{
		text = QInputDialog::getText(this, QString(), tr("Password:"), QLineEdit::Password, QString(), &flag);
		if (text.isEmpty() && flag) {
			QMessageBox::critical(this, tr("Error"), tr("Password can't be empty!"));
			flag = false;
		}			
		else if (text.length() > 32) {
			QMessageBox::critical(this, tr("Error"), tr("Password can't be longer than 32 character"));
			flag = false;
		}
		else {
			flag = true;
		}	
	}

	// pack/unpack
	status = processFile(text);

	if (!status) {
		ui->label->setText("");
		ui->label_2->setText("");
		this->pathDest.clear();
		this->pathSrc.clear();
	}
	else
		QMessageBox::critical(this, tr("Error"), ege::sterror(status, IPP_ID));

}

ERR_STATUS MainWindow::processFile(QString &password)
{
	ERR_STATUS status = NO_ERROR;
	ege::Filer handler;
	std::experimental::filesystem::path src(this->pathSrc); qDebug() << src.extension().string().c_str();

	if (std::experimental::filesystem::is_directory(src)) { // If it is a directory this is a packing
		// Reserved
	}
	else if (strcmp(src.extension().string().c_str(), ".ege")) { // If extension not "ege" this is a packing
		handler.setKey((Ipp8u*)password.toStdString().data(), password.length());
		
		status = handler.setPath(this->pathSrc.data());
		if (status)
			return status;

		handler.setCompressionType(this->comp);
		handler.setEncryptionMethod(this->crypt);
		handler.setHashMethod(this->hash);

		status = handler.pack(this->pathDest.data(), true);
		if (status)
			return status;
	}
	else { // This is an unpacking
		status = handler.setPath(this->pathSrc.data());
		if (status)
			return status;
		handler.setKey((Ipp8u*)password.toStdString().data(), password.length());
		status = handler.unpack(this->pathDest.data(), true);
		if (status)
			return status;
	}
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setPath(int id)
{
	QString fileName;	
	
	switch (id)
	{
	case 1:
	{
		fileName = QFileDialog::getOpenFileName(this);
		ui->label_2->setText(fileName);
		this->pathSrc = fileName.toStdString();
		break;
	}
	case 2:
	{
		fileName = QFileDialog::getSaveFileName(this, tr("Select save location"), this->pathSrc.c_str());
		ui->label->setText(fileName);
		this->pathDest = fileName.toStdString();
		break;
	}
	}
}

