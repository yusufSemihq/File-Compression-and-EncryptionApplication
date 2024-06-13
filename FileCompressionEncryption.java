import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileCompressionEncryption {

    private static final int BUFFER_SIZE = 1024;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void compressAndEncrypt(File inputFile, File outputFile, String password) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        try (FileInputStream fis = new FileInputStream(inputFile);
                FileOutputStream fos = new FileOutputStream(outputFile);
                CipherOutputStream cos = new CipherOutputStream(fos, initCipher(password, Cipher.ENCRYPT_MODE));
                ZipOutputStream zos = new ZipOutputStream(cos)) {

            ZipEntry zipEntry = new ZipEntry(inputFile.getName());
            zos.putNextEntry(zipEntry);

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                zos.write(buffer, 0, bytesRead);
            }
            zos.closeEntry();
        }
    }

    public static void decryptAndDecompress(File inputFile, File outputFile, String password) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        try (FileInputStream fis = new FileInputStream(inputFile);
                ZipInputStream zis = new ZipInputStream(
                        new CipherInputStream(fis, initCipher(password, Cipher.DECRYPT_MODE)));
                FileOutputStream fos = new FileOutputStream(outputFile)) {

            ZipEntry zipEntry = zis.getNextEntry();
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = zis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

    private static Cipher initCipher(String password, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(mode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        return cipher;
    }

    public static void main(String[] args) {
        try {
            File inputFile = new File("input.txt");
            File compressedEncryptedFile = new File("output.zip.enc");

            String password = "secret";

            // Dosyayı sıkıştır ve şifrele
            compressAndEncrypt(inputFile, compressedEncryptedFile, password);

            // Dosyayı çöz ve aç
            File decryptedDecompressedFile = new File("output.txt");
            decryptAndDecompress(compressedEncryptedFile, decryptedDecompressedFile, password);

            System.out.println("İşlem tamamlandı.");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
