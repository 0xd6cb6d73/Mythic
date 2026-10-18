import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {ConsumingServicesTableRow} from './ConsumingServicesTable';

jest.mock('@apollo/client', () => ({...jest.requireActual('@apollo/client'), useMutation: () => [jest.fn()]}));
jest.mock('../../utilities/Snackbar', () => ({snackActions: {success: jest.fn(), error: jest.fn()}}));
jest.mock('../../MythicComponents/MythicDialog', () => ({MythicDialog: () => null}));
jest.mock('../../MythicComponents/MythicAgentSVGIcon', () => ({
    MythicAgentSVGIcon: ({payload_type}) => <span data-testid="service-icon">{payload_type} icon</span>,
}));
jest.mock('./ConsumingServicesGetIDPMetadataDialog', () => ({ConsumingServicesGetIDPMetadataDialog: () => null}));
jest.mock('./C2ProfileListFilesDialog', () => ({C2ProfileListFilesDialog: () => null}));

let container, root;
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

const service = {id: 1, name: 'worker', type: 'crypto', semver: '1.0', container_running: true,
    crypto_capabilities: {schemes: ['example'], api_version: 1}};

test('the External table separates the provider icon, identity, metadata, and actions into five columns', () => {
    act(() => root.render(<table><tbody><ConsumingServicesTableRow service={service} separateIcon /></tbody></table>));
    const cells = container.querySelectorAll('tr:first-child > td');
    expect(cells).toHaveLength(5);
    expect(cells[1].querySelector('[data-testid="service-icon"]')).not.toBeNull();
    expect(cells[2].textContent).toContain('Crypto provider');
    expect(cells[2].querySelector('[data-testid="service-icon"]')).toBeNull();
    expect(cells[3].textContent).toContain('Schemes');
    expect(cells[3].textContent).toContain('example');
    expect(cells[4].textContent).toBe('');
});

test('existing consuming-service tables keep the four-column layout', () => {
    act(() => root.render(<table><tbody><ConsumingServicesTableRow service={{...service, type: 'webhook', subscriptions: []}} /></tbody></table>));
    const cells = container.querySelectorAll('tr:first-child > td');
    expect(cells).toHaveLength(4);
    expect(cells[1].querySelector('[data-testid="service-icon"]')).not.toBeNull();
    expect(cells[1].textContent).toContain('Webhook');
    expect(cells[2].textContent).toContain('Version1.0');
});
