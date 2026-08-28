export type WorkspaceView = 'account' | 'new-browser' | 'trusted-device' | 'transfers';

export const WORKSPACE_VIEWS: WorkspaceView[] = [
    'account',
    'new-browser',
    'trusted-device',
    'transfers',
];

export function nextWorkspaceView(view: WorkspaceView, key: string): WorkspaceView | null {
    const index = WORKSPACE_VIEWS.indexOf(view);
    if (index === -1) {
        return null;
    }
    if (key === 'Home') {
        return WORKSPACE_VIEWS[0];
    }
    if (key === 'End') {
        return WORKSPACE_VIEWS[WORKSPACE_VIEWS.length - 1];
    }
    if (key !== 'ArrowRight' && key !== 'ArrowLeft') {
        return null;
    }
    const direction = key === 'ArrowRight' ? 1 : -1;
    return WORKSPACE_VIEWS[(index + direction + WORKSPACE_VIEWS.length) % WORKSPACE_VIEWS.length];
}
