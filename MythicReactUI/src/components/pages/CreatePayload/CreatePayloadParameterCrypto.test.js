import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {CreatePayloadParameter} from './CreatePayloadParameter';

let mockMutationOptions;
jest.mock('@apollo/client', () => ({
    ...jest.requireActual('@apollo/client'),
    useMutation: (query, options) => {
        mockMutationOptions = options;
        return [() => {}];
    },
}));
jest.mock('../Callbacks/TaskParametersDialogRow', () => ({DragAndDropFileUpload: () => null}));
jest.mock('../../MythicComponents/MythicDialog', () => ({MythicDialog: () => null}));
jest.mock('react-ace', () => () => null);
jest.mock('ace-builds/src-noconflict/mode-json', () => ({}));
jest.mock('ace-builds/src-noconflict/theme-github', () => ({}));
jest.mock('ace-builds/src-noconflict/theme-monokai', () => ({}));
jest.mock('ace-builds/src-noconflict/ext-searchbox', () => ({}));
jest.mock('../../utilities/Snackbar', () => ({snackActions: {warning: jest.fn(), info: jest.fn()}}));
jest.mock('../../MythicComponents/MythicTextField', () => ({__esModule: true,
    default: ({name, value, onChange, placeholder}) => <input aria-label={placeholder || name} value={value || ''}
        onChange={event => onChange(name, event.target.value, false)} />,
}));

let root, container;
beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
});
afterEach(() => {
    act(() => root.unmount());
    container.remove();
});

const render = (props) => act(() => root.render(<CreatePayloadParameter name="AESPSK" description="Encryption Type"
    parameter_type="ChooseOne" trackedValue="" default_value="" choices={[]} crypto_type
    supported_crypto_schemes={[]} displayMode="card" dynamic_query_function="" {...props} />));

test('a legacy crypto dynamic ChooseOne still selects its first returned choice', () => {
    const onChange = jest.fn();
    render({onChange, dynamic_query_function: 'query'});
    act(() => mockMutationOptions.onCompleted({dynamicQueryBuildParameterFunction: {
        status: 'success', choices: ['aes256_hmac', 'none'], complex_choices: [],
    }}));
    expect(onChange).toHaveBeenLastCalledWith('AESPSK', 'aes256_hmac', false);
    expect(container.querySelector('select')).toBeNull();
});

test('clearing a legacy ChooseOneCustom value restores its builtin selection', () => {
    const onChange = jest.fn();
    render({onChange, parameter_type: 'ChooseOneCustom', choices: ['aes256_hmac', 'none'],
        trackedValue: 'legacy-custom', default_value: 'aes256_hmac'});
    const input = container.querySelector('input[aria-label="Custom Value"]');
    expect(input.value).toBe('legacy-custom');
    act(() => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '');
        input.dispatchEvent(new Event('input', {bubbles: true}));
    });
    expect(onChange).toHaveBeenLastCalledWith('AESPSK', 'aes256_hmac', false);
});

test('a provider selection is preserved and flagged when payload scheme support is removed', () => {
    const onChange = jest.fn();
    const value = 'provider:worker:example';
    render({onChange, trackedValue: value, choices: ['aes256_hmac'], default_value: 'aes256_hmac'});
    expect(container.querySelector('select').value).toBe(value);
    expect(container.querySelector('[role="alert"]').textContent).toMatch(/payload type does not support/);
    expect(onChange).toHaveBeenLastCalledWith('AESPSK', value, true);
});
