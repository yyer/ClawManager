import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'
import postcss from 'postcss'
import { adaptations, applyAdaptation } from '../scripts/web-adaptations.mjs'

test('reviewed gates match the locked source exactly, preserve the real entry and parse as TSX', async () => {
  for (const adaptation of adaptations) {
    assert.ok(!['main.tsx', 'app/index.tsx', 'app/routes.ts', 'app/contrib/controller.tsx'].includes(adaptation.file))
    const original = await readFile(new URL(`../.upstream/source/apps/desktop/src/${adaptation.file}`, import.meta.url), 'utf8')
    const patched = applyAdaptation(original, adaptation)
    assert.notEqual(patched, original)
    assert.throws(() => applyAdaptation(patched, adaptation), /anchor changed/)
    if (adaptation.file.endsWith('.css')) {
      assert.doesNotThrow(() => postcss.parse(patched))
      continue
    }
    const result = ts.transpileModule(patched, { fileName: adaptation.file, compilerOptions: { jsx: ts.JsxEmit.ReactJSX }, reportDiagnostics: true })
    assert.equal(result.diagnostics?.filter(row => row.category === ts.DiagnosticCategory.Error).length, 0, adaptation.file)
  }
})

test('managed model switching stays session-scoped and Projects use the Runtime API', async () => {
  const model = adaptations.find((entry: { file: string }) => entry.file === 'app/session/hooks/use-model-controls.ts')
  assert.ok(model)
  const originalModel = await readFile(new URL('../.upstream/source/apps/desktop/src/app/session/hooks/use-model-controls.ts', import.meta.url), 'utf8')
  const patchedModel = applyAdaptation(originalModel, model)
  assert.match(patchedModel, /const scope = '--session'/)
  assert.doesNotMatch(patchedModel, /persistsAsDefault \? '--global'/)

  const projects = adaptations.find((entry: { file: string }) => entry.file === 'store/projects.ts')
  assert.ok(projects)
  const originalProjects = await readFile(new URL('../.upstream/source/apps/desktop/src/store/projects.ts', import.meta.url), 'utf8')
  const patchedProjects = applyAdaptation(originalProjects, projects)
  assert.match(patchedProjects, /projects\.list/)
  assert.match(patchedProjects, /return '\.'/)
  assert.doesNotMatch(patchedProjects, /Project management belongs to the CM workspace/)
})
