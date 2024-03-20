let key;
let iv;

async function generateKey() {
    try {
        key = await window.crypto.subtle.generateKey(
            { name: "AES-CBC", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );
        const exportedKey = await window.crypto.subtle.exportKey("jwk", key);
        localStorage.setItem("cryptoKey", JSON.stringify(exportedKey));
    } catch (error) {
        alert("Error generating key: " + error.message);
    }
}

async function importKey() {
    try {
        const cryptoKey = JSON.parse(localStorage.getItem("cryptoKey"));
        key = await window.crypto.subtle.importKey(
            "jwk",
            cryptoKey,
            { name: "AES-CBC", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        alert("Error importing key: " + error.message);
    }
}

async function encryptString(str) {
    try {
        const encodedString = new TextEncoder().encode(str);
        iv = window.crypto.getRandomValues(new Uint8Array(16));
        localStorage.setItem("iv", JSON.stringify(Array.from(iv)));
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            key,
            encodedString
        );
        return Array.prototype.map.call(new Uint8Array(encryptedData), x => ('00' + x.toString(16)).slice(-2)).join('');
    } catch (error) {
        alert("Error encrypting string: " + error.message);
    }
}

async function decryptString(encryptedData) {
    try {
        iv = new Uint8Array(JSON.parse(localStorage.getItem("iv")));
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            key,
            encryptedData
        );
        return new TextDecoder().decode(decryptedData);
    } catch (error) {
        alert("Error decrypting string: " + error.message);
    }
}

async function encrypt() {
    try {
        await generateKey();
        const input = document.getElementById('input').value;
        const encryptedHex = await encryptString(input);
        document.getElementById('output').innerText = "Encrypted: " + encryptedHex;
    } catch (error) {
        alert("Error during encryption: " + error.message);
    }
}

async function decrypt() {
    try {
        await importKey();
        const input = document.getElementById('input').value;
        const encryptedData = new Uint8Array(input.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const decryptedString = await decryptString(encryptedData);
        document.getElementById('output').innerText = "Decrypted: " + decryptedString;
    } catch (error) {
        alert("Error during decryption: " + error.message);
    }
}