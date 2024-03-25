//
//  ViewController.swift
//  ShieldPackageForX509
//
//  Created by Harish Sami on 07/03/24.
//

import UIKit
import CryptoKit
import CryptoSwift
import Shield
import ShieldX509
import ShieldOID
import PotentASN1
import Crypto
import _CryptoExtras
import X509
import SwiftASN1
import OpenSSL

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        // Step 1: Generate RSA key pair
       /* let privateKey = P256.Signing.PrivateKey()

        // Step 2: Define the subject name for the CSR
        let subjectName = NameBuilder()
            .DirectoryName("Your Common Name")
            .build()

        // Step 3: Create a Certificate Signing Request (CSR)
        let csr = CSRBuilder.newCSR()
            .commonName("Your Common Name")
            .subjectAltName("yourdomain.com")
            .set(key: privateKey)
            .build()

        // Step 4: Convert the CSR to PKCS#10 format
        let pkcs10 = try! csr.toPKCS10()

        // Now you have the PKCS#10 data
        print(pkcs10) */
        
     /*   // Example usage Using OpneSSl
        let commonName = "Harish Sami" // Customize the common name as needed

        if let csr = generateCSR(commonName: commonName) {
            print("Generated CSR:")
            print(csr)
            
            if let token = extractTokenFromCSR(csr) {
                print("Extracted Token:")
                print(token)
            } else {
                print("Failed to extract token from CSR")
            }
        } else {
            print("Failed to generate CSR")
        }
        
        // Generate RSA key pair
        guard let rsa = RSA_generate_key(2048, UInt(RSA_F4), nil, nil) else {
            print("Error generating RSA key pair")
            exit(EXIT_FAILURE)
        }

        // Create a new X509_REQ object
        guard let req = X509_REQ_new() else {
            print("Error creating X509_REQ object")
            exit(EXIT_FAILURE)
        }

        // Set the public key in the certificate request
        guard let pkey = EVP_PKEY_new() else {
            print("Error creating EVP_PKEY object")
            exit(EXIT_FAILURE)
        }

        EVP_PKEY_set1_RSA(pkey, rsa)
        X509_REQ_set_pubkey(req, pkey)

        // Set the subject name (common name)
        guard let name = X509_REQ_get_subject_name(req) else {
            print("Error getting subject name from X509_REQ")
            exit(EXIT_FAILURE)
        }

        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Your Common Name", -1, -1, 0)
        X509_REQ_set_subject_name(req, name)

        // Sign the certificate request
        guard X509_REQ_sign(req, pkey, EVP_sha256()) == 1 else {
            print("Error signing X509_REQ")
            exit(EXIT_FAILURE)
        }

        // Write the certificate request to a file in PEM format
        guard let file = fopen("certificate_request.pem", "wb") else {
            print("Error opening file for writing")
            exit(EXIT_FAILURE)
        }

        let result = PEM_write_X509_REQ(file, req)
        fclose(file)

        if result == 1 {
            print("PKCS#10 certificate request generated successfully")
        } else {
            print("Error writing PKCS#10 certificate request to file")
        }
        
        */
        
        
        if let containerUrl = FileManager.default.url(forUbiquityContainerIdentifier: nil)?.appendingPathComponent("Documents") {
            if !FileManager.default.fileExists(atPath: containerUrl.path, isDirectory: nil) {
                do {
                    try FileManager.default.createDirectory(at: containerUrl, withIntermediateDirectories: true, attributes: nil)
                }
                catch {
                    print(error.localizedDescription)
                }
            }
            
            let fileUrl = containerUrl.appendingPathComponent("applepush.txt")
            do {
                try "Hello iCloud!".write(to: fileUrl, atomically: true, encoding: .utf8)
            }
            catch {
                print(error.localizedDescription)
            }
        }
        
       
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        let documentsDirectory1 = paths[0]
        let docURL = URL(string: documentsDirectory1)!
        let dataPath = docURL.appendingPathComponent("MyFolder")
        if !FileManager.default.fileExists(atPath: dataPath.path) {
            do {
                try FileManager.default.createDirectory(atPath: dataPath.path, withIntermediateDirectories: true, attributes: nil)
            } catch {
                print(error.localizedDescription)
            }
        }
        
         createFileDirectory()
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        print(publicKey.pemRepresentation)
        let dataToSign = "squeamish ossifrage".data(using: .utf8)!
        print("echo \(dataToSign.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > dataToSign.dat")
        let signed = try! privateKey.signature(for: dataToSign)
        let signeddata = "echo \(signed.derRepresentation.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > sig-ck.dat"
        print(signeddata)
     
       try? testSimpleRoundTrip()
        // Define the folder name and file names
        let folderName = "EMM_iOS"
        let fileNames = ["applepush.txt"]

        // Get the document directory URL
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            print("Error: Could not access document directory")
            return
        }

        // Create a URL for the folder
        let folderURL = documentsDirectory.appendingPathComponent(folderName)

        do {
            // Create the folder if it doesn't exist
            try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true, attributes: nil)
            
            // Loop through file names and add files to the folder
            for fileName in fileNames {
                let fileURL = folderURL.appendingPathComponent(fileName)
                
                // Create an empty file at the file URL
                FileManager.default.createFile(atPath: fileURL.path, contents: nil, attributes: nil)
                
//                 Write data to the file if needed
//                 For example:
                 let data = signeddata.data(using: .utf8)
                 try data?.write(to: fileURL)
                print("files created successfully at \(fileURL)")
            }
            
//            print("Folder and files created successfully at \(folderURL)")
        } catch {
            print("Error creating folder and files: \(error)")
        }
        
        
        
        let fileManager = FileManager.default
        let documentsURL =  fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!

        let imagesPath = documentsURL.appendingPathComponent("Images")
        do
        {
            try FileManager.default.createDirectory(atPath: imagesPath.path, withIntermediateDirectories: true, attributes: nil)
        }
        catch let error as NSError
        {
            NSLog("Unable to create directory \(error.debugDescription)")
        }
    }
    
    func createFileDirectory() {
        let documentsURL = try! FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
        
        //set the name of the new folder
        let folderURL = documentsURL.appendingPathComponent("EmmIOS")
        do {
            try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)
            print("Folder UrL====,\(folderURL)")
        }
        catch let error as NSError {
            NSLog("Unable to create directory \(error.debugDescription)")
        }
    }

    func testSimpleRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName {
            CountryName("In")
            OrganizationName("Tectoro Consulting Private Lmited")
            CommonName("Sami Harish")
            
        }
        let extensions = try Certificate.Extensions {
            SubjectAlternativeNames([.dnsName("tectoro.com")])
        }
        let extensionRequest = ExtensionRequest(extensions: extensions)
        let attributes = try CertificateSigningRequest.Attributes(
            [.init(extensionRequest)]
        )
        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: name,
            privateKey: .init(key),
            attributes: attributes,
            signatureAlgorithm: .ecdsaWithSHA256
        )

        let bytes = try DER.Serializer.serialized(element: csr)
        let parsed = try CertificateSigningRequest(derEncoded: bytes)
        print("CSR WITH DER ENCODED,\(parsed)")
        print("CSR WITH Bytes,\(bytes)")


//        XCTAssertEqual(parsed, csr)
    }
    
    // Function to generate a CSR using OpenSSL
    func generateCSR(commonName: String) -> String? {
        // Create an EVP object to hold the private key
        guard let privateKey = EVP_PKEY_new() else {
            print("Error creating EVP_PKEY object")
            return nil
        }
        
        // Create a new RSA key
        guard let rsa = RSA_new() else {
            print("Error creating RSA object")
            return nil
        }
        
        // Generate the RSA key pair
        guard RSA_generate_key_ex(rsa, 2048, nil, nil) == 1 else {
            print("Error generating RSA key pair")
            return nil
        }
        
        // Set the RSA key pair in the EVP object
        EVP_PKEY_set1_RSA(privateKey, rsa)
        
        // Create a new X509 certificate request
        guard let x509Req = X509_REQ_new() else {
            print("Error creating X509_REQ object")
            return nil
        }
        
        // Set the subject name in the certificate request
        let subjectName = X509_NAME_new()
        X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, commonName, -1, -1, 0)
        X509_REQ_set_subject_name(x509Req, subjectName)
        
        // Set the public key in the certificate request
        X509_REQ_set_pubkey(x509Req, privateKey)
        
        print("X509_REQ_set_pubkey,\(x509Req) + \(privateKey)")
        // Sign the certificate request with the private key
        guard X509_REQ_sign(x509Req, privateKey, EVP_sha256()) == 1 else {
            print("Error signing X509_REQ")
            return nil
        }
        
        // Convert the certificate request to PEM format
//        let bio = BIO_new(BIO_s_mem())
//
//        let csrBio = PEM_write_bio_X509_REQ(bio, x509Req)
//        print("Error writing X509_REQ to BIO")
           
        // Initialize a memory-based BIO
        guard let bio = BIO_new(BIO_s_mem()) else {
            // Handle the error here
            print("Error creating memory-based BIO")
            fatalError()
        }
        let csrBio = PEM_write_bio_X509_REQ(bio, x509Req)
      /*
        if csrBio > 0 {
            // Write operation was successful
            // Convert the result to an OpaquePointer
            let csrBioPtr = UnsafeRawPointer(bitPattern: Int(csrBio))
            let csrBioOpaquePtr = csrBioPtr?.assumingMemoryBound(to: OpaquePointer.self)
            
            // Write operation was successful
            // Proceed with your logic
     
        // Read the PEM data from the BIO
            let bufLen = Int(4096) // Buffer length
            var buffer = [CChar](repeating: 0, count: bufLen)
            let unsafePointer: UnsafePointer<OpaquePointer>? = csrBioOpaquePtr
            if let opaquePointer = unsafePointer?.pointee {
                // Now you have the expected OpaquePointer?
                var bytesRead = BIO_read(opaquePointer, &buffer, Int32(bufLen))
                guard bytesRead > 0 else {
                    print("Error reading PEM data from BIO")
                    return nil
                }
                
                // Convert the buffer to Data and then to String
                var pemData = Data(bytes: buffer, count: Int(bytesRead))
                var pemString = String(data: pemData, encoding: .utf8)
                // Cleanup
                BIO_free_all(bio)
                X509_REQ_free(x509Req)
                EVP_PKEY_free(privateKey)
                
                return pemString
            }
        } else {
            // Write operation failed
            print("Error writing X509_REQ to BIO")
        } */
        
        
//            // Write operation was successful
//            // Proceed with your logic
        let csrBioPtr = UnsafeRawPointer(bitPattern: Int(csrBio))
        let csrBioOpaquePtr = csrBioPtr?.assumingMemoryBound(to: OpaquePointer.self)
        print("Error writing X509_REQ to BIO")
     
        // Read the PEM data from the BIO
        let bufLen = Int(4096) // Buffer length
        var buffer = [CChar](repeating: 0, count: bufLen)
        let unsafePointer: UnsafePointer<OpaquePointer>? = csrBioOpaquePtr
        let opaquePointer = unsafePointer?.pointee
        let bytesRead = BIO_read(opaquePointer, &buffer, Int32(bufLen))
        
        guard bytesRead > 0 else {
            print("Error reading PEM data from BIO")
            return nil
        }
        
        // Convert the buffer to Data and then to String
        let pemData = Data(bytes: buffer, count: Int(bytesRead))
        let pemString = String(data: pemData, encoding: .utf8)
        
        // Cleanup
        BIO_free_all(bio)
        X509_REQ_free(x509Req)
        EVP_PKEY_free(privateKey)
        
        return pemString
    }

    // Function to extract the token from the CSR
    func extractTokenFromCSR(_ csr: String) -> String? {
        // Extract token from CSR
        // This depends on the format of your CSR and how the token is structured within it
        // For example, if the token is in the format "TOKEN: <your_token>", you can extract it as follows:
        
        let tokenPattern = #"TOKEN: (.+)"#
        let regex = try! NSRegularExpression(pattern: tokenPattern, options: [])
        let matches = regex.matches(in: csr, options: [], range: NSRange(location: 0, length: csr.utf16.count))
        
        if let match = matches.first {
            let range = Range(match.range(at: 1), in: csr)!
            return String(csr[range])
        } else {
            return nil
        }
    }
}

extension DER.Serializer {
    @inlinable
    static func serialized<Element: DERSerializable>(element: Element) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(element)
        return serializer.serializedBytes
    }
}
