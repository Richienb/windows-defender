"use strict"

const defenderPath = require("defender-path")
const execa = require("execa")
const path = require("path")
const { default: ow } = require("ow")
const { default: is } = require("@sindresorhus/is")
const isAdmin = require("is-admin")

async function forceAdmin() {
	if (!(await isAdmin())) throw new Error("Admin privileges required to run this command.")
}

if (is.null(defenderPath)) throw new Error("Windows Defender not supported on this system!")

const scan = async (dir, { scanBootSector = false, remediate = false, timeout = 1 } = {}) => {
    /*
	[
  {
    threat: 'Virus:DOS/EICAR_Test_File',
    files: [
      'D:\\0 - Richie Bendall\\GitHub\\windows-defender\\f\\eicar.com.txt',
      'D:\\0 - Richie Bendall\\GitHub\\windows-defender\\f\\eicar.com copy.txt'
    ]
  },
  {
    threat: 'Trojan:Win32/Woreflint.A!cl',
    files: [
      'D:\\0 - Richie Bendall\\GitHub\\windows-defender\\f\\edac70a21147f442ce6cc0736c6ea24979e39925ca53782378d91b9c24f3fb54'
    ]
  }
	]
	*/

	ow(dir, ow.string)
	ow(scanBootSector, ow.boolean)
	ow(remediate, ow.boolean)
	ow(timeout, ow.number.is(val => val > 0 && val <= 30))

	const opts = ["-Scan", "-ScanType", "3", "-File", path.resolve(dir), "-Timeout", timeout]

	if (scanBootSector === true) opts.push("-BootSectorScan")
	if (remediate === false) opts.push("-DisableRemediation")

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
		} else {
			throw error
		}
	}
}
scan.quick = ({ timeout = 1 } = {}) => {
	ow(timeout, ow.number.is(val => val > 0 && val <= 30))

	return execa(defenderPath, ["-Scan", "-ScanType", "1", "-Timeout", timeout])
}
scan.quick.cancel = () => execa(defenderPath, ["-Scan", "-ScanType", "1", "-Cancel"])
scan.full = ({ timeout = 7 } = {}) => {
	ow(timeout, ow.number.is(val => val > 0 && val <= 30))

	return execa(defenderPath, ["-Scan", "-ScanType", "2", "-Timeout", timeout])
}
scan.full.cancel = () => execa(defenderPath, ["-Scan", "-ScanType", "2", "-Cancel"])

const definitions = {
	revert: () => execa(defenderPath, ["-RemoveDefinitions"]),
	remove: () => execa(defenderPath, ["-RemoveDefinitions", "-All"]),
	update: (unc) => unc ? execa(defenderPath, ["-SignatureUpdate", "-UNC", path.resolve(unc)]) : execa(defenderPath, ["-SignatureUpdate", "-MMPC"])
}

definitions.revert.engine = () => execa(defenderPath, ["-RemoveDefinitions", "-Engine"])
definitions.remove.dynamicSignatures = () => execa(defenderPath, ["-RemoveDefinitions", "-DynamicSignatures"])

module.exports = {
	scan,
	definitions,
}
