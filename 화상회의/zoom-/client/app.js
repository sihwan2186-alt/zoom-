const EMBED_PROVIDER_DOMAIN = 'meet.jit.si';
const MEETING_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;

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
            const params = new URLSearchParams();

            params.set('config.prejoinConfig.enabled', 'false');
            params.set('config.startWithAudioMuted', 'true');
            params.set('config.startWithVideoMuted', 'true');
            params.set('config.disableThirdPartyRequests', 'true');
            params.set('config.analytics.disabled', 'true');
            params.set('config.analytics.obfuscateRoomName', 'true');
            params.set('config.enableInsecureRoomNameWarning', 'true');
            params.set('config.p2p.enabled', 'false');
            params.set('config.disableDeepLinking', 'true');
            params.set('config.disableInviteFunctions', 'true');
            params.set('config.requireDisplayName', 'false');
            params.set('config.defaultLocalDisplayName', 'SW개발보안 1팀');
            params.set('config.defaultRemoteDisplayName', '참가자');
            params.set('config.hideConferenceSubject', 'true');
            params.set('interfaceConfig.APP_NAME', 'SW개발보안 1팀 SecureMeet');
            params.set('interfaceConfig.NATIVE_APP_NAME', 'SW개발보안 1팀 SecureMeet');
            params.set('interfaceConfig.PROVIDER_NAME', 'SW개발보안 1팀');
            params.set('interfaceConfig.SHOW_JITSI_WATERMARK', 'false');
            params.set('interfaceConfig.SHOW_BRAND_WATERMARK', 'false');
            params.set('interfaceConfig.SHOW_WATERMARK_FOR_GUESTS', 'false');
            params.set('interfaceConfig.SHOW_POWERED_BY', 'false');
            params.set('interfaceConfig.SHOW_PROMOTIONAL_CLOSE_PAGE', 'false');
            params.set('interfaceConfig.SHOW_CHROME_EXTENSION_BANNER', 'false');
            params.set('interfaceConfig.DISPLAY_WELCOME_PAGE_CONTENT', 'false');

            if (options.e2eeEnabled) {
                params.set('config.e2ee.enabled', 'true');
            }
            if (options.lobbyEnabled) {
                params.set('config.enableLobby', 'true');
            }

            return `https://${EMBED_PROVIDER_DOMAIN}/${encodeURIComponent(meetingId)}#${params.toString()}`;
        }

        function activateConference(conferenceUrl, meetingId) {
            const frame = document.getElementById('conference-frame');
            const shell = document.getElementById('conference-shell');
            const activeMeetingLabel = document.getElementById('active-meeting-label');

            frame.src = conferenceUrl;
            frame.title = `SW개발보안 1팀 SecureMeet 회의 화면 - ${meetingId}`;
            shell.classList.add('is-live');
            activeMeetingLabel.textContent = `회의실 ${meetingId}`;
        }

// 탭 전환
function showTab(tabName, triggerElement) {
    const targetContent = document.getElementById(`${tabName}-tab`);
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

    const contentContainer = targetContent.parentElement;
    contentContainer.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    targetContent.classList.add('active');
}
        
        // 로그인
        function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const mfaEnabled = document.getElementById('mfa-enabled').checked;
            
            if (!username || !password) {
                alert('사용자 이름과 비밀번호를 입력해주세요.');
                return;
            }
            
            // 실제 구현에서는 서버와 통신
            console.log('로그인 시도:', { mfaEnabled });
            
            // 회의실 화면으로 전환
            document.getElementById('login-screen').style.display = 'none';
            document.getElementById('meeting-screen').style.display = 'block';
        }
        
        // 회원가입
        function register() {
            const username = document.getElementById('reg-username').value;
            const email = document.getElementById('reg-email').value;
            const password = document.getElementById('reg-password').value;
            
            if (!username || !email || !password) {
                alert('모든 필드를 입력해주세요.');
                return;
            }
            
            // 실제 구현에서는 서버와 통신
            console.log('회원가입 요청');
            alert('회원가입이 완료되었습니다.');
        }
        
        // 회의 참여
        function joinMeeting() {
            const meetingId = document.getElementById('meeting-id').value;
            
            if (!meetingId || !validateMeetingId(meetingId)) {
                alert('회의실 ID는 8~64자의 영문/숫자/하이픈/밑줄만 사용할 수 있습니다.');
                return;
            }
            
            const conferenceUrl = buildConferenceUrl(meetingId);
            
            activateConference(conferenceUrl, meetingId);
            console.log('회의 참여 요청');
        }
        
        // 회의 생성
        function createMeeting() {
            const meetingName = document.getElementById('new-meeting-name').value;
            const e2eeEnabled = document.getElementById('e2ee-enabled').checked;
            const lobbyEnabled = document.getElementById('lobby-enabled').checked;
            
            if (!meetingName) {
                alert('회의실 이름을 입력해주세요.');
                return;
            }
            
            const meetingId = generateSecureMeetingId();
            
            const conferenceUrl = buildConferenceUrl(meetingId, { e2eeEnabled, lobbyEnabled });
            
            activateConference(conferenceUrl, meetingId);
            console.log('회의 생성 요청:', { e2eeEnabled, lobbyEnabled });
        }
        
        // 보안 모듈 통합 (Python/Java와 연동 시)
        class SecurityClient {
            constructor() {
                this.encryptionEnabled = true;
                this.mfaEnabled = true;
            }
            
            async encryptMessage(message) {
                // Python 암호화 모듈과 연동
                console.log('메시지 암호화:', message);
                return message;
            }
            
            async validateSession() {
                // Java 인증 모듈과 연동
                console.log('세션 검증');
                return true;
            }
        }
        
// 보안 클라이언트 초기화
const securityClient = new SecurityClient();

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab-target]').forEach(tab => {
        tab.addEventListener('click', () => showTab(tab.dataset.tabTarget, tab));
    });

    document.getElementById('login-button')?.addEventListener('click', login);
    document.getElementById('register-button')?.addEventListener('click', register);
    document.getElementById('join-meeting-button')?.addEventListener('click', joinMeeting);
    document.getElementById('create-meeting-button')?.addEventListener('click', createMeeting);
});
