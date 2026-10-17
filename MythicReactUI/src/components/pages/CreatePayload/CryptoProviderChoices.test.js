import {getBuildCryptoError, getCryptoChoices, getCryptoParameterError, getCryptoSelectionError} from './CryptoProviderChoices';

const provider = (name, schemes, online = true) => ({
    name, container_running: online, crypto_capabilities: {api_version: 1, schemes},
});
const discovery = (providers, extra = {}) => ({providers, loading: false, error: null, ...extra});
const value = 'provider:custom-worker:example';

test('preserves builtin values, order, display labels, and default while appending compatible providers', () => {
    const choices = ['none', 'aes256_hmac'];
    const providers = discovery([
        provider('custom-worker', ['example', 'unsupported']),
        provider('other-worker', ['example']),
        provider('offline-worker', ['example'], false),
    ]);
    const options = getCryptoChoices(choices, {none: 'Unencrypted', aes256_hmac: 'AES-256'}, ['example'], providers, 'aes256_hmac');
    expect(options).toEqual([
        {value: 'none', label: 'Unencrypted', disabled: false},
        {value: 'aes256_hmac', label: 'AES-256', disabled: false},
        {value, label: 'example (custom-worker)', disabled: false},
        {value: 'provider:other-worker:example', label: 'example (other-worker)', disabled: false},
    ]);
    expect(choices).toEqual(['none', 'aes256_hmac']);
    expect(getCryptoSelectionError('aes256_hmac', [], providers)).toBe('');
    expect(getCryptoSelectionError('none', [], providers)).toBe('');
});

test('requires agent opt-in even when a matching provider is installed or listed in static choices', () => {
    const providers = discovery([provider('custom-worker', ['example'])]);
    expect(getCryptoChoices(['aes256_hmac', value], {}, [], providers, 'aes256_hmac').map(option => option.value)).toEqual(['aes256_hmac']);
    expect(getCryptoSelectionError(value, undefined, providers)).toMatch(/payload type does not support/);
});

test('retains a saved or custom builtin value outside the listed choices', () => {
    const providers = discovery([]);
    const options = getCryptoChoices(['aes256_hmac'], {}, [], providers, 'legacy-custom');
    expect(options[options.length - 1]).toEqual({value: 'legacy-custom', label: 'legacy-custom', disabled: false});
    expect(getCryptoSelectionError('legacy-custom', [], providers)).toBe('');
});

test('an empty String crypto parameter remains empty while provider choices load', () => {
    const providers = discovery([provider('custom-worker', ['example'])]);
    expect(getCryptoChoices([], {}, ['example'], providers, '').some(option => option.value === '' && !option.disabled)).toBe(true);
});

test('validates required and regex-constrained legacy values while providers use compatibility validation', () => {
    const providers = discovery([provider('custom-worker', ['example'])]);
    const parameter = {required: true, verifier_regex: '^[a-f0-9]{4}$'};
    expect(getCryptoParameterError({...parameter, value: ''}, ['example'], providers)).toMatch(/required/);
    expect(getCryptoParameterError({...parameter, value: 'abcd'}, ['example'], providers)).toBe('');
    expect(getCryptoParameterError({...parameter, value: 'not-a-key'}, ['example'], providers)).toMatch(/Must match/);
    expect(getCryptoParameterError({...parameter, value}, ['example'], providers)).toBe('');
});

test.each([
    [discovery([]), /unavailable/],
    [discovery([provider('custom-worker', ['example'], false)]), /unavailable/],
    [discovery([provider('custom-worker', ['changed'])]), /no longer supports/],
    [discovery([], {loading: true}), /Loading/],
    [discovery([], {error: new Error('Disconnected')}), /discovery is unavailable/],
])('retains unavailable imported selections as disabled options and blocks them', (providers, message) => {
    const options = getCryptoChoices(['aes256_hmac'], {}, ['example'], providers, value);
    expect(options[options.length - 1]).toEqual({value, label: 'example (custom-worker) — unavailable', disabled: true});
    expect(getCryptoSelectionError(value, ['example'], providers)).toMatch(message);
    expect(getCryptoSelectionError('aes256_hmac', ['example'], providers)).toBe('');
});

test('does not accept malformed qualified selections', () => {
    const providers = discovery([provider('custom-worker', ['example'])]);
    expect(getCryptoSelectionError('provider:custom-worker:example:extra', ['example'], providers)).toMatch(/Invalid/);
});

test('checks both payload and C2 parameters while ignoring inactive parameters and ordinary strings', () => {
    const providers = discovery([provider('custom-worker', ['example'], false)]);
    const crypto = {name: 'encryption', crypto_type: true, value};
    const build = {1: {os: 'Linux', supported_crypto_schemes: ['example'], parameters: [crypto]}};
    expect(getBuildCryptoError(build, providers)).toMatch(/encryption:.*unavailable/);
    build[1].parameters = [{...crypto, crypto_type: false}];
    expect(getBuildCryptoError(build, providers)).toBe('');
    build[3] = {c2: [{name: 'transport', c2profileparameters: [crypto]}]};
    expect(getBuildCryptoError(build, providers)).toMatch(/unavailable/);
    build[3].c2[0].c2profileparameters = [{...crypto, supported_os: ['Windows']}];
    expect(getBuildCryptoError(build, providers)).toBe('');
});
