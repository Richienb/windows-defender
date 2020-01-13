"use strict"

const defenderPath = require("defender-path")
const execa = require("execa")
const path = require("path")
const { default: ow } = require("ow")
const { default: is } = require("@sindresorhus/is")

if (is.null(defenderPath)) throw new Error("Windows Defender not supported on this system!")

const scan = () => execa(defenderPath, ["-Scan", "-ScanType", "0"])
scan.quick = () => execa(defenderPath, ["-Scan", "-ScanType", "1"])
scan.quick.cancel = () => execa(defenderPath, ["-Scan", "-ScanType", "1", "-Cancel"])
scan.full = () => execa(defenderPath, ["-Scan", "-ScanType", "2"])
scan.quick.cancel = () => execa(defenderPath, ["-Scan", "-ScanType", "2", "-Cancel"])
scan.custom = async (dir, { scanBootSector = false, remediate = false } = {}) => {
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

	const opts = ["-Scan", "-ScanType", "3", "-File", path.resolve(dir)]

	if (scanBootSector === true) opts.push("-BootSectorScan")
	if (remediate === false) opts.push("-DisableRemediation")

	try {
		await execa(defenderPath, opts)
		return []
	} catch (error) {
		const { stdout, code } = error
		if (code === 2) {
			return stdout.split("\r\n").slice(5, -1).join("\n").split(/^-*$/gm).slice(0, -1).map((res) => ({
				threat: res.match(/Threat *: (?<threat>.+)/).groups.threat,
				files: res.match(/file *: (.+)/g).map((file) => file.match(/file *: (?<file>.+)/).groups.file),
			}))
		} else {
			throw error
		}
	}
}
scan.cancel = () => execa(defenderPath, ["-Scan", "-ScanType", "0", "-Cancel"])

module.exports = {
	scan,
}
