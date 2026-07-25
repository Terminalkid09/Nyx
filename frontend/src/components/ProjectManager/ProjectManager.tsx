import { useState, useEffect, useRef } from 'react'
import { FolderOpen, Download, Upload, Plus, Trash2 } from 'lucide-react'
import {
  fetchProjects,
  createProject,
  deleteProject,
  exportProject,
  importProject,
} from '../../api/endpoints/projects'
import { Project } from '../../types'

export function ProjectManager() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showNewForm, setShowNewForm] = useState(false)
  const [newProject, setNewProject] = useState({ name: '', description: '', session_id: '' })
  const [exporting, setExporting] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const loadProjects = () => {
    setLoading(true)
    setError('')
    fetchProjects()
      .then(setProjects)
      .catch((err: any) => setError(err.response?.data?.detail || err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadProjects() }, [])

  const handleCreate = async () => {
    if (!newProject.name) return
    try {
      const created = await createProject({
        name: newProject.name,
        description: newProject.description || undefined,
        session_id: newProject.session_id || undefined,
      })
      setProjects((prev) => [...prev, created])
      setShowNewForm(false)
      setNewProject({ name: '', description: '', session_id: '' })
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteProject(id)
      setProjects((prev) => prev.filter((p) => p.id !== id))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleExport = async (project: Project) => {
    setExporting(project.id)
    setError('')
    try {
      const blob = await exportProject(project.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${project.name.replace(/[^a-zA-Z0-9_-]/g, '_')}.nyx`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setExporting(null)
    }
  }

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setError('')
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      const imported = await importProject(data)
      setProjects((prev) => [...prev, imported])
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to import project')
    }
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleOpenProject = (project: Project) => {
    // Open project functionality - would navigate or load project context
    console.log('Open project:', project.id)
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <FolderOpen size={16} />
        <span>Project Manager</span>
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowNewForm(!showNewForm)}
            className="flex items-center gap-1 bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium"
          >
            <Plus size={14} /> New Project
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1 bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-xs font-medium"
          >
            <Upload size={14} /> Import
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".nyx,application/json"
            className="hidden"
            onChange={handleImport}
          />
        </div>

        {showNewForm && (
          <div className="bg-gray-900 border border-gray-700 rounded p-3 space-y-2">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Name</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                value={newProject.name}
                onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                placeholder="Project name"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Description</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                value={newProject.description}
                onChange={(e) => setNewProject({ ...newProject, description: e.target.value })}
                placeholder="Optional description"
              />
            </div>
            <button
              onClick={handleCreate}
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50"
              disabled={!newProject.name}
            >
              Create
            </button>
          </div>
        )}

        {loading ? (
          <div className="text-xs text-gray-500">Loading...</div>
        ) : projects.length === 0 ? (
          <div className="text-xs text-gray-500">
            No projects yet. Create a new project or import one.
          </div>
        ) : (
          <div className="space-y-2">
            {projects.map((project) => (
              <div
                key={project.id}
                className="bg-gray-900 border border-gray-800 rounded p-3 hover:border-gray-700"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-200">{project.name}</span>
                      {project.session_id && (
                        <span className="text-xs text-gray-500 font-mono">
                          session: {project.session_id.slice(0, 8)}...
                        </span>
                      )}
                    </div>
                    {project.description && (
                      <div className="text-xs text-gray-500 mt-0.5 truncate">{project.description}</div>
                    )}
                    <div className="text-xs text-gray-600 mt-1">
                      Created: {new Date(project.created_at).toLocaleString()}
                      {project.updated_at !== project.created_at && ` · Updated: ${new Date(project.updated_at).toLocaleString()}`}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 ml-3">
                    <button
                      onClick={() => handleOpenProject(project)}
                      className="p-1 text-blue-400 hover:text-blue-300"
                      title="Open"
                    >
                      <FolderOpen size={14} />
                    </button>
                    <button
                      onClick={() => handleExport(project)}
                      disabled={exporting === project.id}
                      className="p-1 text-gray-400 hover:text-gray-300 disabled:opacity-50"
                      title="Export"
                    >
                      <Download size={14} />
                    </button>
                    <button
                      onClick={() => handleDelete(project.id)}
                      className="p-1 text-red-400 hover:text-red-300"
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
