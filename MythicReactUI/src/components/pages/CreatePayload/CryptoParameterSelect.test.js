import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {CryptoParameterSelect} from './CryptoParameterSelect';

let mockDiscovery;
jest.mock('./CryptoProviderContext', () => ({useCryptoProviders: () => mockDiscovery}));

const selectedProvider = 'provider:worker:example';
const provider = {name: 'worker', container_running: true, crypto_capabilities: {schemes: ['example']}};
let container, root;

beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    mockDiscovery = {providers: [provider], loading: false, error: null};
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
});

afterEach(() => {
    act(() => root.unmount());
    container.remove();
});

const render = (value, onChange) => act(() => root.render(
    <CryptoParameterSelect name="crypto" description="Encryption" choices={['aes256_hmac', 'none']}
        choices_display_names={{aes256_hmac: 'AES-256'}} default_value="aes256_hmac"
        trackedValue={value} supported_crypto_schemes={['example']} onChange={onChange} />
));

test('preserves the builtin default and emits the exact qualified provider selection on interaction', () => {
    const onChange = jest.fn();
    render('aes256_hmac', onChange);
    const select = container.querySelector('select');
    expect(select.value).toBe('aes256_hmac');
    expect(Array.from(select.options, option => option.text)).toEqual(['AES-256', 'none', 'example (worker)']);
    act(() => {
        select.value = selectedProvider;
        select.dispatchEvent(new Event('change', {bubbles: true}));
    });
    expect(onChange).toHaveBeenLastCalledWith('crypto', selectedProvider, false);
});

test('provider disappearance preserves the selection and marks it invalid without falling back to AES', () => {
    const onChange = jest.fn();
    render(selectedProvider, onChange);
    expect(container.querySelector('select').value).toBe(selectedProvider);
    onChange.mockClear();
    mockDiscovery = {...mockDiscovery, providers: []};
    render(selectedProvider, onChange);
    expect(container.querySelector('select').value).toBe(selectedProvider);
    expect(container.querySelector('select').selectedOptions[0].disabled).toBe(true);
    expect(container.querySelector('[role="alert"]').textContent).toMatch(/unavailable/);
    expect(onChange).toHaveBeenLastCalledWith('crypto', selectedProvider, true);
    expect(onChange.mock.calls.every(([, value]) => value === selectedProvider)).toBe(true);
});

test('an imported selection survives initial discovery loading and becomes valid without user changes', () => {
    const onChange = jest.fn();
    mockDiscovery = {...mockDiscovery, providers: [], loading: true};
    render(selectedProvider, onChange);
    expect(container.querySelector('select').value).toBe(selectedProvider);
    expect(onChange).toHaveBeenLastCalledWith('crypto', selectedProvider, true);
    mockDiscovery = {providers: [provider], loading: false, error: null};
    render(selectedProvider, onChange);
    expect(container.querySelector('select').value).toBe(selectedProvider);
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(onChange).toHaveBeenLastCalledWith('crypto', selectedProvider, false);
});

test('ChooseOneCustom retains manual builtin values alongside provider discovery', () => {
    const onChange = jest.fn();
    act(() => root.render(
        <CryptoParameterSelect name="crypto" description="Encryption" choices={['aes256_hmac', 'none']}
            default_value="aes256_hmac" trackedValue="legacy-custom" supported_crypto_schemes={['example']}
            onChange={onChange} allowCustom />
    ));
    expect(container.querySelector('select').value).toBe('legacy-custom');
    const input = container.querySelector('textarea[aria-label="Custom encryption value"]');
    expect(input.value).toBe('legacy-custom');
    act(() => {
        const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setValue.call(input, 'another-legacy-value');
        input.dispatchEvent(new Event('input', {bubbles: true}));
    });
    expect(onChange).toHaveBeenLastCalledWith('crypto', 'another-legacy-value', false);
});

test('String crypto keeps its empty custom field and validates manual keys without choosing a provider implicitly', () => {
    const onChange = jest.fn();
    act(() => root.render(
        <CryptoParameterSelect name="crypto" description="Encryption" choices={[]}
            default_value="" trackedValue="" supported_crypto_schemes={['example']}
            onChange={onChange} allowCustom required verifier_regex="^[a-f0-9]{4}$" />
    ));
    expect(container.querySelector('select').value).toBe('');
    expect(container.querySelector('[role="alert"]').textContent).toMatch(/required/);
    const input = container.querySelector('textarea[aria-label="Custom encryption value"]');
    act(() => {
        const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setValue.call(input, 'abcd');
        input.dispatchEvent(new Event('input', {bubbles: true}));
    });
    expect(onChange).toHaveBeenLastCalledWith('crypto', 'abcd', false);
    act(() => {
        const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setValue.call(input, 'invalid');
        input.dispatchEvent(new Event('input', {bubbles: true}));
    });
    expect(onChange).toHaveBeenLastCalledWith('crypto', 'invalid', true);
});

test('refreshing dynamic builtin choices and labels does not reset the current selection', () => {
    const onChange = jest.fn();
    render(selectedProvider, onChange);
    onChange.mockClear();
    act(() => root.render(
        <CryptoParameterSelect name="crypto" description="Encryption" choices={['new-builtin']}
            choices_display_names={{'new-builtin': 'New builtin'}} default_value="aes256_hmac"
            trackedValue={selectedProvider} supported_crypto_schemes={['example']} onChange={onChange} />
    ));
    expect(container.querySelector('select').value).toBe(selectedProvider);
    expect(Array.from(container.querySelector('select').options, option => option.text)).toEqual(['New builtin', 'example (worker)']);
    expect(onChange).not.toHaveBeenCalled();
});
