import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [text, setText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [encryptedSessionKey, setEncryptedSessionKey] = useState('');
  const [result, setResult] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [error, setError] = useState('');
  const [showFullPublicKey, setShowFullPublicKey] = useState(false);
  const [showFullPrivateKey, setShowFullPrivateKey] = useState(false);
  const [digest, setDigest] = useState('');
  const [hash, setHash] = useState('');
  const [signature, setSignature] = useState('');
  const [otherPublicKeys, setOtherPublicKeys] = useState({});
  const [selectedOtherKeyId, setSelectedOtherKeyId] = useState(null);

  useEffect(() => {
    const fetchKeys = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/generate-keys', {
          headers: { 'Content-Type': 'application/json' },
        });
        console.log('Keys response:', response.data);
        setPublicKey(response.data.rsa_public_key);
        setPrivateKey(response.data.rsa_private_key);
        setError('');
      } catch (error) {
        console.error('Error fetching keys:', error.response ? error.response.data : error.message);
        setError(`Failed to load keys. Details: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
      }
    };
    fetchKeys();
  }, []);

  const generateDigest = (text) => {
    if (!text) return '';
    return text
      .split(' ')
      .map(word => {
        let result = '';
        for (let i = 2; i < word.length; i += 3) {
          result += word[i] || '';
        }
        return result;
      })
      .join('');
  };

  const handleEncrypt = async () => {
    if (!publicKey || !privateKey) {
      setError('Ключи не сгенерированы. Пожалуйста, подождите...');
      return;
    }
    const calculatedDigest = generateDigest(text);
    setDigest(calculatedDigest);
    try {
      const hashResponse = await axios.post('http://localhost:5000/api/hash', {
        digest: calculatedDigest,
      }, {
        headers: { 'Content-Type': 'application/json' },
      });
      const { hash: computedHash } = hashResponse.data;
      setHash(computedHash);
      console.log(`Hash: ${computedHash}`);

      const signResponse = await axios.post('http://localhost:5000/api/sign', {
        hash: computedHash,
      }, {
        headers: { 'Content-Type': 'application/json' },
      });
      const { signature: computedSignature } = signResponse.data;
      setSignature(computedSignature);
      console.log(`Signature: ${computedSignature}`);

      const encryptResponse = await axios.post('http://localhost:5000/api/encrypt', {
        text: text,
        digest: calculatedDigest,
      }, {
        headers: { 'Content-Type': 'application/json' },
      });
      const { encrypted_text, encrypted_session_key, signature } = encryptResponse.data;
      setEncryptedText(`${encrypted_session_key}||${encrypted_text}`);
      setEncryptedSessionKey(encrypted_session_key);
      setResult(`${encrypted_session_key}||${encrypted_text}`);
      setError('');
    } catch (error) {
      console.error('Error:', error.response ? error.response.data : error.message);
      setError(`Ошибка. Детали: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
  };

  const handleDecrypt = async () => {
    if (!encryptedText) {
      setError('Введите зашифрованный текст');
      return;
    }
    const [encryptedSessionKey, encryptedTextPart] = result.split('||');
    if (!encryptedSessionKey || !encryptedTextPart) {
      setError('Некорректный формат зашифрованного текста');
      return;
    }
    try {
      const response = await axios.post('http://localhost:5000/api/decrypt', {
        encrypted_text: encryptedTextPart,
        encrypted_session_key: encryptedSessionKey,
        signature: signature,
        digest: digest,
      }, {
        headers: { 'Content-Type': 'application/json' },
      });
      const { decrypted, signature_valid } = response.data;
      setResult(`Decrypted: ${decrypted}, Signature Valid: ${signature_valid}`);
      setError('');
    } catch (error) {
      console.error('Error decrypting:', error.response ? error.response.data : error.message);
      setError(`Ошибка дешифрования. Детали: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
  };

  const exportKey = (key, keyType) => {
    const blob = new Blob([key], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${keyType}_key.pem`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };

  const copyToClipboard = (key) => {
    navigator.clipboard.writeText(key).then(() => {
      alert('Copied to clipboard!');
    }).catch(err => {
      setError(`Failed to copy: ${err.message}`);
    });
  };

  const exportDigest = () => {
    const blob = new Blob([digest], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'digest.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };

  const copyDigestToClipboard = () => {
    navigator.clipboard.writeText(digest).then(() => {
      alert('Digest copied to clipboard!');
    }).catch(err => {
      setError(`Failed to copy digest: ${err.message}`);
    });
  };

  const handleImportKey = (event, keyType) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const keyContent = e.target.result;
        try {
          if (keyType === 'public' && !keyContent.includes('-----BEGIN RSA PUBLIC KEY-----')) {
            throw new Error('Неверный формат публичного ключа');
          }
          if (keyType === 'private' && !keyContent.includes('-----BEGIN RSA PRIVATE KEY-----')) {
            throw new Error('Неверный формат приватного ключа');
          }
          if (keyType === 'public') {
            setPublicKey(keyContent);
          } else if (keyType === 'private') {
            setPrivateKey(keyContent);
          }
          setError('');
        } catch (err) {
          setError(`Ошибка импорта: ${err.message}`);
        }
      };
      reader.readAsText(file);
      event.target.value = '';
    }
  };

  const exportResults = () => {
    const results = {
      digest,
      hash,
      signature,
      encryptedSessionKey,
      encryptedText,
      result,
    };
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'crypto_results.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="App">
      <h1>Crypto App</h1>

      <div className="keys-section">
        <h3>Keys</h3>
        <p>
          <strong>Public Key:</strong> {showFullPublicKey ? publicKey : `${publicKey.substring(0, 50)}...`}
          <button className="show-full-btn" onClick={() => setShowFullPublicKey(!showFullPublicKey)}>
            {showFullPublicKey ? 'Скрыть' : 'Показать полностью'}
          </button>
        </p>
        <button onClick={() => exportKey(publicKey, 'public')} style={{ marginRight: '10px' }}>
          Export Public Key
        </button>
        <button onClick={() => copyToClipboard(publicKey)} style={{ marginRight: '10px' }}>
          Copy Public Key
        </button>
        <label>
          Import Public Key
          <input type="file" onChange={(e) => handleImportKey(e, 'public')} accept=".pem" />
        </label>
        <p>
          <strong>Private Key:</strong> {showFullPrivateKey ? privateKey : `${privateKey.substring(0, 50)}...`}
          <button className="show-full-btn" onClick={() => setShowFullPrivateKey(!showFullPrivateKey)}>
            {showFullPrivateKey ? 'Скрыть' : 'Показать полностью'}
          </button>
        </p>
        <button onClick={() => exportKey(privateKey, 'private')} style={{ marginRight: '10px' }}>
          Export Private Key
        </button>
        <button onClick={() => copyToClipboard(privateKey)} style={{ marginRight: '10px' }}>
          Copy Private Key
        </button>
        <label>
          Import Private Key
          <input type="file" onChange={(e) => handleImportKey(e, 'private')} accept=".pem" />
        </label>
        {error && <p className="error"><strong>Error:</strong> {error}</p>}
      </div>

      <div className="encrypt-section">
        <h3>Encrypt</h3>
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Enter text to encrypt"
        />
        <button onClick={handleEncrypt}>Encrypt</button>
        <p><strong>Digest:</strong> {digest}</p>
        <p><strong>Hash:</strong> {hash}</p>
        <p><strong>Signature:</strong> {signature}</p>
        <p><strong>Encrypted Session Key:</strong> {encryptedSessionKey}</p>
        <p><strong>Encrypted Text:</strong> {encryptedText}</p>
        <button onClick={exportDigest} style={{ marginRight: '10px' }}>
          Export Digest
        </button>
        <button onClick={copyDigestToClipboard} style={{ marginRight: '10px' }}>
          Copy Digest
        </button>
        <button onClick={exportResults}>
          Export All Results
        </button>
      </div>

      <div className="decrypt-section">
        <h3>Decrypt</h3>
        <input
          type="text"
          value={encryptedText}
          onChange={(e) => setEncryptedText(e.target.value)}
          placeholder="Enter encrypted text"
        />
        <button onClick={handleDecrypt}>Decrypt</button>
      </div>

      <div className="result-section">
        <p><strong>Result:</strong> {result}</p>
      </div>
    </div>
  );
}

export default App;