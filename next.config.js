/** @type {import('next').NextConfig} */
const nextConfig = {
	...(process.env.PORTABLE_BUILD === '1'
		? {
				output: 'export',
				typescript: {
					ignoreBuildErrors: true,
				},
			}
		: {}),
}

module.exports = nextConfig
