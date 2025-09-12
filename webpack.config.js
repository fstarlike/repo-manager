const path = require("path");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

module.exports = (env, argv) => {
    const isProduction = argv.mode === "production";

    return {
        entry: {
            admin: "./src/Assets/js/admin.js",
            "floating-widget": "./src/Assets/js/floating-widget.js",
            "rtl-support": "./src/Assets/js/rtl-support.js",
            troubleshoot: "./src/Assets/js/troubleshoot.js",
        },
        output: {
            path: path.resolve(__dirname, "dist/js"),
            filename: "[name].min.js",
            clean: false,
        },
        module: {
            rules: [
                {
                    test: /\.scss$/,
                    use: [
                        MiniCssExtractPlugin.loader,
                        "css-loader",
                        {
                            loader: "postcss-loader",
                            options: {
                                postcssOptions: {
                                    plugins: [require("autoprefixer")],
                                },
                            },
                        },
                        "sass-loader",
                    ],
                },
            ],
        },
        plugins: [
            new MiniCssExtractPlugin({
                filename: "../css/[name].min.css",
            }),
        ],
        optimization: {
            minimize: isProduction,
        },
        devtool: isProduction ? false : "source-map",
        externals: {
            jquery: "jQuery",
        },
    };
};
