#!/usr/bin/env python3
import unittest
import os
import shutil
import subprocess
from unittest.mock import patch, MagicMock
import easyca

class TestEasyCA(unittest.TestCase):
    BASE_DIR = "./test_ca_data"
    
    @classmethod
    def setUpClass(cls):
        """Prepare the test environment."""
        if os.path.exists(cls.BASE_DIR):
            shutil.rmtree(cls.BASE_DIR)
        os.makedirs(cls.BASE_DIR, exist_ok=True)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests."""
        shutil.rmtree(cls.BASE_DIR)

    @patch("easyca.run_command")
    def test_create_ca(self, mock_run_command):
        """Test the creation of a root CA."""
        mock_run_command.return_value = ""
        args = MagicMock(basedir=self.BASE_DIR, days=3650)
        easyca.create_ca("TestRootCA", "US", "California", "San Francisco", "TestOrg", args=args)
        self.assertTrue(os.path.exists(f"{self.BASE_DIR}/ca/TestRootCA/ca.crt"))
        self.assertTrue(os.path.exists(f"{self.BASE_DIR}/ca/TestRootCA/ca.key"))
    
    @patch("easyca.run_command")
    def test_create_csr(self, mock_run_command):
        """Test the creation of a CSR."""
        mock_run_command.return_value = ""
        args = MagicMock(basedir=self.BASE_DIR)
        easyca.create_csr("test.example.com", ["www.test.example.com"], "US", "California", "San Francisco", "TestOrg", args=args)
        self.assertTrue(os.path.exists(f"{self.BASE_DIR}/csr/test.example.com.csr"))
        self.assertTrue(os.path.exists(f"{self.BASE_DIR}/csr/test.example.com.key"))
    
    @patch("easyca.run_command")
    def test_sign_csr(self, mock_run_command):
        """Test signing a CSR."""
        mock_run_command.return_value = ""
        args = MagicMock(basedir=self.BASE_DIR, days=365)
        # Create required files
        os.makedirs(f"{self.BASE_DIR}/ca/TestRootCA", exist_ok=True)
        os.makedirs(f"{self.BASE_DIR}/csr", exist_ok=True)
        with open(f"{self.BASE_DIR}/ca/TestRootCA/ca.crt", "w") as f:
            f.write("DUMMY CERT")
        with open(f"{self.BASE_DIR}/ca/TestRootCA/ca.key", "w") as f:
            f.write("DUMMY KEY")
        with open(f"{self.BASE_DIR}/csr/test.example.com.csr", "w") as f:
            f.write("DUMMY CSR")
        
        easyca.sign_csr("TestRootCA", "test.example.com", args=args)
        self.assertTrue(os.path.exists(f"{self.BASE_DIR}/certs/test.example.com.crt"))
    
    @patch("easyca.run_command")
    def test_show_cert(self, mock_run_command):
        """Test showing certificate details."""
        mock_run_command.return_value = "Certificate details output"
        args = MagicMock(basedir=self.BASE_DIR)
        
        os.makedirs(f"{self.BASE_DIR}/certs", exist_ok=True)
        with open(f"{self.BASE_DIR}/certs/test.example.com.crt", "w") as f:
            f.write("DUMMY CERT")
        
        with patch("builtins.print") as mock_print:
            easyca.show_cert("test.example.com", args)
            mock_print.assert_called_with("Certificate details output")
    
    @patch("easyca.get_root_ca")
    @patch("easyca.run_command")
    def test_is_sub_ca(self, mock_run_command, mock_get_root_ca):
        """Test checking if a CA is a sub-CA."""
        mock_run_command.side_effect = ["ISSUER_HASH", "CA:TRUE", "ROOT_HASH"]
        mock_get_root_ca.return_value = "TestRootCA"
        args = MagicMock(basedir=self.BASE_DIR)
        os.makedirs(f"{self.BASE_DIR}/ca/TestSubCA", exist_ok=True)
        with open(f"{self.BASE_DIR}/ca/TestSubCA/ca.crt", "w") as f:
            f.write("DUMMY CERT")
        self.assertTrue(easyca.is_sub_ca("TestSubCA", args))
    
if __name__ == "__main__":
    unittest.main()
