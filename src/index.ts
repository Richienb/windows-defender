"use strict"

import path from "path"
import defenderPath from "defender-path"
import execa from "execa"
import isAdmin from "is-admin"
import cleanSplit from "clean-split"
import fs from "fs-extra"
import ow from "ow"
import is from "@sindresorhus/is"

/** @private */
async function forceAdmin(): Promise<void> {
	if (!(await isAdmin())) throw new Error("Admin privileges are required to execute this function.");
}

if (is.null_(defenderPath)) throw new Error("Windows Defender not supported on this system!");

interface Threat {
	threat: string;
	files: string[];
}

export async function isExcluded(dir: string): Promise<boolean> {
	await forceAdmin()
	ow(dir, ow.string)
	try {
		await execa(defenderPath, ["-CheckExclusion", "-Path", path.resolve(dir)])
		return true
	} catch (error) {
		return false
	}
}

export namespace definitions {
	export async function removeAll(): Promise<void> {
		await forceAdmin()
		await execa(defenderPath, ["-RemoveDefinitions", "-All"])
	}

	export async function revert(): Promise<void> {
		await forceAdmin()
		await execa(defenderPath, ["-RemoveDefinitions"])
	}

	export async function update(unc?: string): Promise<void> {
		ow(unc, ow.optional.string)
		if (unc) await execa(defenderPath, ["-SignatureUpdate", "-UNC", path.resolve(unc)])
		else await execa(defenderPath, ["-SignatureUpdate", "-MMPC"])
	}

	export namespace dynamicSignatures {
		export async function add(path: string): Promise<void> {
			await forceAdmin()
			ow(path, ow.string)
			await execa(defenderPath, ["-AddDynamicSignature", "-Path", path])
		}
		export async function remove(id?: string): Promise<void> {
			await forceAdmin()
			ow(id, ow.optional.string)
			if (is.string(id)) await execa(defenderPath, ["-RemoveDynamicSignature", "-SignatureSetID", id])
			else await execa(defenderPath, ["-RemoveDefinitions", "-DynamicSignatures"])
		}
	}

	export namespace revert {
		export async function engine(): Promise<void> {
			await forceAdmin()
			await execa(defenderPath, ["-RemoveDefinitions", "-Engine"])
		}
	}

}

interface QuarantinedThreat {
	threat: string;
	files: Array<{
		file: string;
		time: string;
	}>;
}

export namespace quarantine {
	export async function list(): Promise<QuarantinedThreat[]> {
		await forceAdmin()
		const { stdout } = await execa(defenderPath, ["-Restore", "-ListAll"])
		return cleanSplit(stdout
			.split("\r\n")
			.slice(2)
			.filter((line) => line !== "")
			.join("\n"), /ThreatName = .+/g, { anchor: "right" })
			.map((entry) => ({
				threat: entry.match(/ThreatName = (?<threat>.+)/).groups.threat,
				files: entry.match(/ +(.+)/g).map((file) => file.match(/ +(?<file>.+)/).groups.file).slice(1).map((file) => ({ ...file.match(/(?<file>.+) quarantined at (?<time>.+)/).groups })),
			})) as QuarantinedThreat[]
	}

	export async function restore(name: string, restoreDir?: string) {
		await forceAdmin()
		ow(name, ow.string)
		ow(restoreDir, ow.optional.string)
		const exists = await fs.pathExists(path.resolve(name))
		const opts = ["-Restore", exists ? "-Path" : "-Name", exists ? path.resolve(name) : name]
		if (is.string(restoreDir)) {
			opts.push("-FilePath");
			opts.push(path.resolve(restoreDir))
		}

		await execa(defenderPath, opts)
	}

	export namespace restore {
		export async function all(): Promise<void> {
			await forceAdmin()
			await execa(defenderPath, ["-Restore", "-All"])
		}
	}
}

export async function scan(dir: string, {
	scanBootSector = false,
	remediate = false,
	timeout = 1,
}: {
	scanBootSector?: boolean;
	remediate?: boolean;
	timeout?: number;
} = {}): Promise<Threat[]> {
	ow(dir, ow.string)
	ow(scanBootSector, ow.boolean)
	ow(remediate, ow.boolean)
	ow(timeout, ow.number.is((val) => val > 0 && val <= 30))

	const opts = ["-Scan", "-ScanType", "3", "-File", path.resolve(dir), "-Timeout", timeout.toString()]

	if (scanBootSector === true) opts.push("-BootSectorScan");
	if (remediate === false) opts.push("-DisableRemediation");

	try {
		await execa(defenderPath, opts)
		return []
	} catch (error) {
		const { stdout, code } = error
		if (code === 2) {
			if (stdout.startsWith("CmdTool")) throw error
			return stdout.split("\r\n").slice(5, -1).join("\n").split(/^-*$/gm).slice(0, -1).map((res) => ({
				threat: res.match(/Threat *: (?<threat>.+)/).groups.threat,
				files: res.match(/file *: (.+)/g).map((file) => file.match(/file *: (?<file>.+)/).groups.file),
			}))
		}

		throw error
	}
}

export namespace scan {

	export async function full({ timeout = 7 }: {
		timeout?: number;
	} = {}): Promise<void> {
		ow(timeout, ow.number.inRange(1, 29))

		await execa(defenderPath, ["-Scan", "-ScanType", "2", "-Timeout", timeout.toString()])
	}

	export async function quick({ timeout = 1 }: {
		timeout?: number;
	} = {}): Promise<void> {
		ow(timeout, ow.number.is((val) => val > 0 && val <= 30))

		await execa(defenderPath, ["-Scan", "-ScanType", "1", "-Timeout", timeout.toString()])
	}

	export namespace full {
		export async function cancel(): Promise<void> {
			await execa(defenderPath, ["-Scan", "-ScanType", "2", "-Cancel"])
		}
	}

	export namespace quick {
		export async function cancel(): Promise<void> {
			await execa(defenderPath, ["-Scan", "-ScanType", "1", "-Cancel"])
		}
	}

}


