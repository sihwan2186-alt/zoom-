const EMBED_PROVIDER_DOMAIN = 'meet.jit.si';
const MEETING_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;

function getElement(id) {
    return document.getElementById(id);
}

function validateMeetingId(meetingId) {
    return MEETING_ID_PATTERN.test(meetingId);
}

function generateSecureMeetingId() {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    const randomId = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

    return `secure-${randomId}`;
}

function buildConferenceUrl(meetingId, options = {}) {
    const params = new URLSearchParams({
        'config.prejoinConfig.enabled': 'false',
        'config.startWithAudioMuted': 'true',
        'config.startWithVideoMuted': 'true',
        'config.disableThirdPartyRequests': 'true',
        'config.analytics.disabled': 'true',
        'config.analytics.obfuscateRoomName': 'true',
        'config.enableInsecureRoomNameWarning': 'true',
        'config.p2p.enabled': 'false',
        'config.disableDeepLinking': 'true',
        'config.disableInviteFunctions': 'true',
        'config.requireDisplayName': 'false',
        'config.defaultLocalDisplayName': 'SW개발보안 1팀',
        'config.defaultRemoteDisplayName': '참가자',
        'config.hideConferenceSubject': 'true',
        'interfaceConfig.APP_NAME': 'SW개발보안 1팀 SecureMeet',
        'interfaceConfig.NATIVE_APP_NAME': 'SW개발보안 1팀 SecureMeet',
        'interfaceConfig.PROVIDER_NAME': 'SW개발보안 1팀',
        'interfaceConfig.SHOW_JITSI_WATERMARK': 'false',
        'interfaceConfig.SHOW_BRAND_WATERMARK': 'false',
        'interfaceConfig.SHOW_WATERMARK_FOR_GUESTS': 'false',
        'interfaceConfig.SHOW_POWERED_BY': 'false',
        'interfaceConfig.SHOW_PROMOTIONAL_CLOSE_PAGE': 'false',
        'interfaceConfig.SHOW_CHROME_EXTENSION_BANNER': 'false',
        'interfaceConfig.DISPLAY_WELCOME_PAGE_CONTENT': 'false',
    });

    if (options.e2eeEnabled) {
        params.set('config.e2ee.enabled', 'true');
    }
    if (options.lobbyEnabled) {
        params.set('config.enableLobby', 'true');
    }

    return `https://${EMBED_PROVIDER_DOMAIN}/${encodeURIComponent(meetingId)}#${params.toString()}`;
}

function activateConference(conferenceUrl, meetingId) {
    const frame = getElement('conference-frame');
    const shell = getElement('conference-shell');
    const activeMeetingLabel = getElement('active-meeting-label');

    frame.src = conferenceUrl;
    frame.title = `SW개발보안 1팀 SecureMeet 회의 화면 - ${meetingId}`;
    shell.classList.add('is-live');
    activeMeetingLabel.textContent = `회의실 ${meetingId}`;
}

function showTab(tabName, triggerElement) {
    const targetContent = getElement(`${tabName}-tab`);

    if (!targetContent) {
        return;
    }

    const tabGroup = triggerElement?.closest('.tabs');
    if (tabGroup) {
        tabGroup.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        triggerElement.classList.add('active');
    }

    targetContent.parentElement.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    targetContent.classList.add('active');
}

function login() {
    const username = getElement('username').value.trim();
    const password = getElement('password').value;

    if (!username || !password) {
        alert('사용자 이름과 비밀번호를 입력해주세요.');
        return;
    }

    getElement('login-screen').style.display = 'none';
    getElement('meeting-screen').style.display = 'block';
}

function register() {
    const username = getElement('reg-username').value.trim();
    const email = getElement('reg-email').value.trim();
    const password = getElement('reg-password').value;

    if (!username || !email || !password) {
        alert('모든 필드를 입력해주세요.');
        return;
    }

    alert('로컬 데모 계정 입력값이 확인되었습니다. 실제 계정 저장은 서버 구현 범위입니다.');
}

function joinMeeting() {
    const meetingId = getElement('meeting-id').value.trim();

    if (!meetingId || !validateMeetingId(meetingId)) {
        alert('회의실 ID는 8~64자의 영문/숫자/하이픈/밑줄만 사용할 수 있습니다.');
        return;
    }

    activateConference(buildConferenceUrl(meetingId), meetingId);
}

function createMeeting() {
    const meetingName = getElement('new-meeting-name').value.trim();
    const e2eeEnabled = getElement('e2ee-enabled').checked;
    const lobbyEnabled = getElement('lobby-enabled').checked;

    if (!meetingName) {
        alert('회의실 이름을 입력해주세요.');
        return;
    }

    const meetingId = generateSecureMeetingId();
    const conferenceUrl = buildConferenceUrl(meetingId, { e2eeEnabled, lobbyEnabled });

    activateConference(conferenceUrl, meetingId);
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab-target]').forEach(tab => {
        tab.addEventListener('click', () => showTab(tab.dataset.tabTarget, tab));
    });

    getElement('login-button')?.addEventListener('click', login);
    getElement('register-button')?.addEventListener('click', register);
    getElement('join-meeting-button')?.addEventListener('click', joinMeeting);
    getElement('create-meeting-button')?.addEventListener('click', createMeeting);
});
