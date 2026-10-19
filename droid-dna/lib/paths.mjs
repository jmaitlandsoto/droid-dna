import { homedir } from 'node:os'
import { join } from 'node:path'

export const HOME = process.env.DROID_DNA_HOME || join(homedir(), '.droid-dna')
export const TOOLS = join(HOME, 'tools')
export const JDK_DIR = join(TOOLS, 'jdk')
export const JADX_JAR = join(TOOLS, 'jadx-headless-mcp-0.7.1-all.jar')
export const ENV_FILE = join(HOME, '.env')
export const CATALOG = join(HOME, 'catalog.json')
export const SAMPLES = join(HOME, 'samples')
export const SCANS = join(HOME, 'scans')
export const REPORTS = join(HOME, 'reports')
export const NODE_DIR = join(TOOLS, 'node')
