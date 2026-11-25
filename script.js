
const API_URL =
  "https://tzptiqxfq6.execute-api.us-east-1.amazonaws.com";

let challengeId = null;
let challengeExpiresAt = 0;
let accessToken = null;
let currentUsername = "";
let timerInterval = null;
let tokenSetupRequired = false;
let otpGenerated = false;
let sessionVersion = 0;
let requestBusy = false;

const pages = document.querySelectorAll(".page");
const messageBox = document.getElementById("message");

function element(id) {
  return document.getElementById(id);
}

function showMessage(text, type = "error") {
  messageBox.textContent = text;
  messageBox.className = `message ${type}`;
}

function clearMessage() {
  messageBox.textContent = "";
  messageBox.className = "message";
}

function setLoading(form, loading) {
  const button = form.querySelector(
    'button[type="submit"]'
  );

  if (!button) return;

  if (loading) {
    button.dataset.originalText = button.textContent;
    button.textContent = "Please wait...";
    button.disabled = true;
  } else {
    button.textContent =
      button.dataset.originalText || "Continue";

    button.disabled = false;
  }
}

async function apiRequest(path, data) {
  let response;

  try {
    response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      cache: "no-store",
      body: JSON.stringify(data)
    });
  } catch {
    throw new Error(
      "Cannot connect to AWS. Check your connection."
    );
  }

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error(
      "Invalid response from AWS server."
    );
  }

  if (!response.ok) {
    throw new Error(
      result.message || `Request failed (${response.status})`
    );
  }

  return result;
}

function clearVirtualToken() {
  element("virtualTokenInfo").hidden = true;
  element("challengeDisplay").textContent = "••••••";

  element("tokenSetupForm").hidden = true;
  element("tokenGenerateForm").hidden = true;

  element("tokenSetupForm").reset();
  element("tokenGenerateForm").reset();
  element("otpForm").reset();

  otpGenerated = false;
}

function clearChallenge() {
  challengeId = null;
  challengeExpiresAt = 0;
  tokenSetupRequired = false;

  if (timerInterval !== null) {
    clearInterval(timerInterval);
    timerInterval = null;
  }

  element("otpTimer").textContent = "05:00";

  clearVirtualToken();
}

function resetSession() {
  sessionVersion++;

  clearChallenge();

  accessToken = null;
  currentUsername = "";
  requestBusy = false;

  element("loginForm").reset();
  element("otpForm").reset();

  element("dashboardUsername").textContent = "User";
  element("sessionStatus").textContent = "Inactive";
}

function showPage(pageId) {
  pages.forEach(page => {
    page.classList.toggle(
      "active",
      page.id === pageId
    );
  });

  clearMessage();

  if (pageId !== "otpPage") {
    clearVirtualToken();

    if (timerInterval !== null) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }
}

function validChallenge() {
  return Boolean(
    challengeId &&
    Date.now() < challengeExpiresAt
  );
}

function updateTokenUI() {
  const button = element("virtualTokenBtn");
  const instructions = element("tokenInstructions");
  const intro = element("setupIntro");

  if (!validChallenge()) {
    button.disabled = true;
    button.textContent = "✦ Virtual Token Unavailable";
    intro.hidden = true;
    return;
  }

  button.disabled = requestBusy || otpGenerated;

  if (tokenSetupRequired) {
    button.textContent = "✦ Set Up Virtual Token";
    instructions.textContent =
      "First-time user? Create a separate Virtual Token PIN to activate your token.";
    intro.hidden = false;
  } else {
    button.textContent = otpGenerated
      ? "✓ OTP Generated"
      : "✦ Generate Virtual OTP";

    instructions.textContent =
      "Enter your personal Virtual Token PIN to generate an OTP for this login.";

    intro.hidden = true;
  }
}

function startOtpTimer() {
  if (timerInterval !== null) {
    clearInterval(timerInterval);
  }

  function updateTimer() {
    if (!challengeId) return;

    const remaining = Math.max(
      0,
      Math.ceil(
        (challengeExpiresAt - Date.now()) / 1000
      )
    );

    const minutes = String(
      Math.floor(remaining / 60)
    ).padStart(2, "0");

    const seconds = String(
      remaining % 60
    ).padStart(2, "0");

    element("otpTimer").textContent =
      `${minutes}:${seconds}`;

    if (remaining === 0) {
      sessionVersion++;
      clearChallenge();

      element("otpForm").querySelector(
        'button[type="submit"]'
      ).disabled = true;

      updateTokenUI();

      showMessage(
        "Your challenge expired. Please log in again."
      );
    }
  }

  updateTimer();

  if (challengeId) {
    timerInterval = setInterval(updateTimer, 1000);
  }
}

document.querySelectorAll("[data-page]").forEach(button => {
  button.addEventListener("click", () => {
    const target = button.dataset.page;

    if (target === "loginPage") {
      resetSession();
    }

    if (target === "registerPage") {
      resetSession();
    }

    showPage(target);
    updateTokenUI();
  });
});

element("registerForm").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    const form = event.currentTarget;

    const username = element("registerUsername")
      .value.trim().toLowerCase();

    const password = element("registerPassword").value;
    const confirm = element("confirmPassword").value;

    if (password !== confirm) {
      showMessage("Passwords do not match.");
      return;
    }

    if (password.length < 12) {
      showMessage(
        "Password must contain at least 12 characters."
      );
      return;
    }

    setLoading(form, true);

    try {
      const result = await apiRequest("/register", {
        username,
        password
      });

      form.reset();
      resetSession();
      showPage("loginPage");

      element("loginUsername").value = username;

      showMessage(
        result.message ||
          "Registration successful. Please log in.",
        "success"
      );

    } catch (error) {
      showMessage(error.message);
    } finally {
      setLoading(form, false);
    }
  }
);

element("loginForm").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    const form = event.currentTarget;

    const username = element("loginUsername")
      .value.trim().toLowerCase();

    const password = element("loginPassword").value;

    resetSession();

    const version = sessionVersion;

    setLoading(form, true);

    try {
      const result = await apiRequest("/login", {
        username,
        password
      });

      if (version !== sessionVersion) return;

      if (!result.mfaRequired || !result.challengeId) {
        throw new Error(
          "AWS did not return a valid MFA challenge."
        );
      }

      currentUsername = username;
      challengeId = result.challengeId;
      challengeExpiresAt = Date.now() + 300000;

      tokenSetupRequired =
        result.tokenSetupRequired === true;

      accessToken = null;

      clearVirtualToken();

      const verifyButton = element("otpForm")
        .querySelector('button[type="submit"]');

      verifyButton.disabled = false;

      showPage("otpPage");
      updateTokenUI();
      startOtpTimer();

      if (tokenSetupRequired) {
        showMessage(
          "Welcome! Set up your Virtual Token PIN first.",
          "success"
        );
      } else {
        showMessage(
          "Password verified. Generate your Virtual OTP.",
          "success"
        );
      }

    } catch (error) {
      if (version === sessionVersion) {
        clearChallenge();
        showMessage(error.message);
      }
    } finally {
      setLoading(form, false);
    }
  }
);

element("virtualTokenBtn").addEventListener(
  "click",
  () => {
    if (!validChallenge()) {
      showMessage(
        "Challenge expired. Please log in again."
      );
      return;
    }

    if (requestBusy || otpGenerated) return;

    clearMessage();

    element("tokenSetupForm").hidden = true;
    element("tokenGenerateForm").hidden = true;

    if (tokenSetupRequired) {
      element("tokenSetupForm").hidden = false;
    } else {
      element("tokenGenerateForm").hidden = false;
    }
  }
);

element("cancelSetupBtn").addEventListener(
  "click",
  () => {
    element("tokenSetupForm").reset();
    element("tokenSetupForm").hidden = true;
    clearMessage();
  }
);

element("cancelGenerateBtn").addEventListener(
  "click",
  () => {
    element("tokenGenerateForm").reset();
    element("tokenGenerateForm").hidden = true;
    clearMessage();
  }
);

element("tokenSetupForm").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    if (requestBusy) return;

    if (!validChallenge()) {
      showMessage(
        "Challenge expired. Please log in again."
      );
      return;
    }

    const form = event.currentTarget;

    const password = element("setupPassword").value;
    const pin = element("setupPin").value;
    const confirmPin = element("confirmPin").value;

    if (pin.length < 8 || pin.length > 128) {
      showMessage(
        "Token PIN must contain 8-128 characters."
      );
      return;
    }

    if (pin !== confirmPin) {
      showMessage("Virtual Token PINs do not match.");
      return;
    }

    if (pin === password) {
      showMessage(
        "Token PIN must differ from your login password."
      );
      return;
    }

    const version = sessionVersion;
    const username = currentUsername;

    requestBusy = true;
    setLoading(form, true);
    updateTokenUI();

    try {
      const result = await apiRequest("/token-setup", {
        username,
        password,
        tokenPin: pin
      });

      if (version !== sessionVersion) return;

      if (!validChallenge()) {
        throw new Error(
          "Challenge expired. Please log in again."
        );
      }

      tokenSetupRequired = false;

      form.reset();
      form.hidden = true;

      element("tokenGenerateForm").hidden = false;

      showMessage(
        result.message ||
          "Virtual Token enrolled successfully!",
        "success"
      );

    } catch (error) {
      if (version === sessionVersion) {
        showMessage(error.message);
      }
    } finally {
      requestBusy = false;
      setLoading(form, false);
      updateTokenUI();
    }
  }
);

element("tokenGenerateForm").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    if (requestBusy || otpGenerated) return;

    if (!validChallenge()) {
      showMessage(
        "Challenge expired. Please log in again."
      );
      return;
    }

    const form = event.currentTarget;
    const pin = element("generatePin").value;

    if (!pin) {
      showMessage("Enter your Virtual Token PIN.");
      return;
    }

    const version = sessionVersion;
    const requestedChallenge = challengeId;

    requestBusy = true;
    setLoading(form, true);
    updateTokenUI();

    try {
      const result = await apiRequest(
        "/token-generate",
        {
          challengeId: requestedChallenge,
          tokenPin: pin
        }
      );

      if (
        version !== sessionVersion ||
        requestedChallenge !== challengeId
      ) {
        return;
      }

      if (!validChallenge()) {
        throw new Error(
          "Challenge expired. Please log in again."
        );
      }

      const otp = String(result.otp);

      if (!/^\d{6}$/.test(otp)) {
        throw new Error(
          "AWS returned an invalid OTP."
        );
      }

      element("challengeDisplay").textContent = otp;
      element("virtualTokenInfo").hidden = false;

      form.reset();
      form.hidden = true;

      otpGenerated = true;

      showMessage(
        "OTP generated! Enter the six-digit code above.",
        "success"
      );

    } catch (error) {
      if (version !== sessionVersion) return;

      if (
        error.message ===
        "Virtual Token enrollment required"
      ) {
        tokenSetupRequired = true;

        form.reset();
        form.hidden = true;

        element("tokenSetupForm").hidden = false;

        showMessage(
          "Please set up your Virtual Token first."
        );
      } else {
        showMessage(error.message);
      }

    } finally {
      requestBusy = false;
      setLoading(form, false);
      updateTokenUI();
    }
  }
);

element("otpForm").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    if (requestBusy) return;

    const form = event.currentTarget;
    const otp = element("otpInput").value.trim();

    if (!validChallenge()) {
      showMessage(
        "Challenge expired. Please log in again."
      );
      return;
    }

    if (!/^\d{6}$/.test(otp)) {
      showMessage(
        "Please enter exactly six digits."
      );
      return;
    }

    const version = sessionVersion;
    const requestedChallenge = challengeId;

    requestBusy = true;
    setLoading(form, true);

    try {
      const result = await apiRequest(
        "/verify-otp",
        {
          challengeId: requestedChallenge,
          otp
        }
      );

      if (
        version !== sessionVersion ||
        requestedChallenge !== challengeId
      ) {
        return;
      }

      if (!result.accessToken) {
        throw new Error(
          "AWS did not issue a session token."
        );
      }

      accessToken = result.accessToken;

      const verifiedUsername = currentUsername;

      clearChallenge();

      element("loginPassword").value = "";

      element("dashboardUsername").textContent =
        verifiedUsername;

      element("sessionStatus").textContent =
        "Demo session issued";

      showPage("dashboardPage");

      showMessage(
        "Authentication successful!",
        "success"
      );

    } catch (error) {
      if (version === sessionVersion) {
        showMessage(error.message);
      }
    } finally {
      requestBusy = false;
      setLoading(form, false);
    }
  }
);

element("logoutBtn").addEventListener(
  "click",
  () => {
    resetSession();
    showPage("loginPage");
    updateTokenUI();

    showMessage(
      "Signed out successfully.",
      "success"
    );
  }
);

window.addEventListener("pagehide", () => {
  resetSession();
});

updateTokenUI();
