const axios = require("axios");
const fs = require("fs").promises;

const API = "http://192.168.31.50:5000/";

async function loadPacketData() {
  try {
    const data = await fs.readFile("attack.json", "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error("Error reading packets.json:", error.message);
    throw error;
  }
}

async function sendU2RPacket(packetData) {
  try {
    const response = await axios.post(API, packetData.u2r, {
      headers: { "Content-Type": "application/json" },
    });
    console.log("U2R Response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Error sending U2R packet:", error.message);
    throw error;
  }
}

async function sendR2LPacket(packetData) {
  try {
    const response = await axios.post(API, packetData.r2l, {
      headers: { "Content-Type": "application/json" },
    });
    console.log("R2L Response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Error sending R2L packet:", error.message);
    throw error;
  }
}

async function sendDDoSPacket(packetData) {
  try {
    const response = await axios.post(API, packetData.ddos, {
      headers: { "Content-Type": "application/json" },
    });
    console.log("DDoS Response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Error sending DDoS packet:", error.message);
    throw error;
  }
}

async function sendProbePacket(packetData) {
  try {
    const response = await axios.post(API, packetData.probe, {
      headers: { "Content-Type": "application/json" },
    });
    console.log("Probe Response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Error sending Probe packet:", error.message);
    throw error;
  }
}

async function sendPacket(attackType) {
  const packetData = await loadPacketData();

  switch (attackType.toLowerCase()) {
    case "u2r":
      return await sendU2RPacket(packetData);
    case "r2l":
      return await sendR2LPacket(packetData);
    case "ddos":
      return await sendDDoSPacket(packetData);
    case "probe":
      return await sendProbePacket(packetData);
    default:
      throw new Error(
        "Invalid attack type. Choose from: u2r, r2l, ddos, probe"
      );
  }
}

// Example usage
(async () => {
  try {
    await sendPacket("u2r");
    await sendPacket("r2l");
    await sendPacket("ddos");
    await sendPacket("probe");
  } catch (error) {
    console.error("Error:", error.message);
  }
})();
