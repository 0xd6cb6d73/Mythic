import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {PayloadTypeBuildParameterInstancesDialog} from './SavedParameterInstancesDialog';

let mockConfig, mockSavedInstance, mockConfigQuery;
const mockProvider = {name: 'worker', container_running: true, crypto_capabilities: {schemes: ['example']}};
jest.mock('@apollo/client', () => ({
    ...jest.requireActual('@apollo/client'),
    useQuery: (query, options) => {
        mockConfigQuery = query;
        require('react').useEffect(() => options.onCompleted(mockConfig), []);
        return {loading: false};
    },
    useLazyQuery: (query, options) => [() => options.onCompleted(mockSavedInstance)],
    useMutation: () => [jest.fn()],
    useSubscription: () => ({data: {consuming_container: [mockProvider]}, loading: false, error: null}),
}));
jest.mock('../CreatePayload/CreatePayloadC2ProfileParametersTable', () => ({CreatePayloadC2ProfileParametersTable: () => null}));
jest.mock('../CreatePayload/CreatePayloadBuildParametersTable', () => ({
    CreatePayloadBuildParametersTable: ({buildParameters, supported_crypto_schemes, onChange}) => {
        const {CryptoParameterSelect} = jest.requireActual('../CreatePayload/CryptoParameterSelect');
        return buildParameters.map(parameter => <CryptoParameterSelect key={parameter.name} {...parameter}
            supported_crypto_schemes={supported_crypto_schemes} onChange={onChange} />);
    },
}));
jest.mock('../../MythicComponents/MythicFileUpload', () => ({UploadTaskFile: jest.fn()}));
jest.mock('../../utilities/Clipboard', () => ({downloadFileFromMemory: jest.fn()}));
jest.mock('../../utilities/Snackbar', () => ({snackActions: {warning: jest.fn(), info: jest.fn()}}));
jest.mock('@mui/material/Select', () => ({__esModule: true,
    default: ({value, onChange, children, inputProps, label}) => <select {...inputProps} aria-label={inputProps?.['aria-label'] || label}
        value={value} onChange={onChange}>{children}</select>,
}));
jest.mock('@mui/material/MenuItem', () => ({__esModule: true,
    default: ({value, children}) => <option value={value}>{children}</option>,
}));

const parameter = {id: 7, name: 'AESPSK', description: 'Encryption Type', parameter_type: 'ChooseOne',
    default_value: 'aes256_hmac', choices: ['aes256_hmac'], crypto_type: true, required: true, verifier_regex: ''};
let container, root;
beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    mockConfig = {payloadtype_by_pk: {supported_crypto_schemes: ['example'], buildparameters: [parameter]},
        buildparameterinstance: [{instance_name: 'saved-provider', id: 1}]};
    mockSavedInstance = {buildparameterinstance: [{id: 1, buildparameter: parameter, value: 'provider:worker:example'}]};
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
});
afterEach(() => {
    act(() => root.unmount());
    container.remove();
});

test('saved build parameters discover compatible providers and keep a loaded provider selection valid', () => {
    act(() => root.render(<PayloadTypeBuildParameterInstancesDialog id={1} name="agent" onClose={() => {}} />));
    expect(mockConfigQuery.loc.source.body).toMatch(/payloadtype_by_pk\(id: \$id\)\s*\{\s*supported_crypto_schemes/);
    let crypto = container.querySelector('select[aria-label="Encryption Type"]');
    expect(Array.from(crypto.options, option => option.value)).toContain('provider:worker:example');
    const instances = container.querySelector('select[aria-label="Select an Existing Instance"]');
    act(() => {
        instances.value = 'saved-provider';
        instances.dispatchEvent(new Event('change', {bubbles: true}));
    });
    crypto = container.querySelector('select[aria-label="Encryption Type"]');
    expect(crypto.value).toBe('provider:worker:example');
    expect(crypto.selectedOptions[0].disabled).toBe(false);
    expect(container.querySelector('[role="alert"]')).toBeNull();
});
